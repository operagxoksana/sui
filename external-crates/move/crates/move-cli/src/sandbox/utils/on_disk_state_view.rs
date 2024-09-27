// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{DEFAULT_BUILD_DIR, DEFAULT_STORAGE_DIR};
use anyhow::{anyhow, bail, Result};
use move_binary_format::file_format::{CompiledModule, FunctionDefinitionIndex};
use move_bytecode_utils::module_cache::GetModule;
use move_command_line_common::files::MOVE_COMPILED_EXTENSION;
use move_core_types::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
    language_storage::{ModuleId, StructTag},
    resolver::{ModuleResolver, ResourceResolver},
};
use move_disassembler::disassembler::Disassembler;
use move_ir_types::location::Spanned;
use move_vm_runtime::{cache::linkage_context::LinkageContext, on_chain::ast::PackageStorageId};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

/// subdirectory of `DEFAULT_STORAGE_DIR`/<addr> where packages are stored
pub const PACKAGES_DIR: &str = "package";

/// file under `DEFAULT_BUILD_DIR` where a registry of generated struct layouts are stored
pub const STRUCT_LAYOUTS_FILE: &str = "struct_layouts.yaml";

#[derive(Debug)]
pub struct OnDiskStateView {
    build_dir: PathBuf,
    storage_dir: PathBuf,
}

impl OnDiskStateView {
    /// Create an `OnDiskStateView` that reads/writes resource data and packages in `storage_dir`.
    pub fn create<P: Into<PathBuf>>(build_dir: P, storage_dir: P) -> Result<Self> {
        let build_dir = build_dir.into();
        if !build_dir.exists() {
            fs::create_dir_all(&build_dir)?;
        }

        let storage_dir = storage_dir.into();
        if !storage_dir.exists() {
            fs::create_dir_all(&storage_dir)?;
        }

        Ok(Self {
            build_dir,
            // it is important to canonicalize the path here because `is_data_path()` relies on the
            // fact that storage_dir is canonicalized.
            storage_dir: storage_dir.canonicalize()?,
        })
    }

    pub fn build_dir(&self) -> &PathBuf {
        &self.build_dir
    }

    pub fn struct_layouts_file(&self) -> PathBuf {
        self.build_dir.join(STRUCT_LAYOUTS_FILE)
    }

    fn is_data_path(&self, p: &Path, parent_dir: &str) -> bool {
        if !p.exists() {
            return false;
        }
        let p = p.canonicalize().unwrap();
        p.starts_with(&self.storage_dir)
            && match p.parent() {
                Some(parent) => parent.ends_with(parent_dir),
                None => false,
            }
    }

    pub fn is_package_path(&self, p: &Path) -> bool {
        self.is_data_path(p, PACKAGES_DIR)
    }

    fn get_package_path(&self, addr: &PackageStorageId) -> PathBuf {
        let mut path = self.storage_dir.clone();
        path.push(format!("0x{}", addr));
        path.push(PACKAGES_DIR);
        path
    }

    pub fn storage_id_of_path(&self, p: &Path) -> Option<PackageStorageId> {
        if !self.is_package_path(p) {
            return None;
        }

        p.parent()
            .and_then(|p| p.file_stem())
            .and_then(|a| a.to_str())
            .and_then(|a| AccountAddress::from_hex_literal(a).ok())
    }

    fn get_module_path(&self, package_id: &PackageStorageId, module_name: &IdentStr) -> PathBuf {
        let mut path = self.get_package_path(package_id);
        path.push(module_name.as_str());
        path.with_extension(MOVE_COMPILED_EXTENSION)
    }

    /// Extract a module ID from a path
    pub fn get_module_id(&self, p: &Path) -> Option<ModuleId> {
        if !self.is_package_path(p) {
            return None;
        }
        let name = Identifier::new(p.file_stem().unwrap().to_str().unwrap()).unwrap();
        match p.parent().and_then(|parent| parent.parent()) {
            Some(parent) => {
                let addr =
                    AccountAddress::from_hex_literal(parent.file_stem().unwrap().to_str().unwrap())
                        .unwrap();
                Some(ModuleId::new(addr, name))
            }
            None => None,
        }
    }

    fn get_package_bytes_at_path(
        &self,
        path: &Path,
    ) -> Result<Option<BTreeMap<Identifier, Vec<u8>>>> {
        if !self.is_package_path(path) {
            return Ok(None);
        }
        let mut modules = BTreeMap::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let name = Identifier::new(path.file_stem().unwrap().to_str().unwrap()).unwrap();
            if path.is_file() {
                modules.insert(name, Self::get_bytes(&path)?.unwrap());
            }
        }
        Ok(Some(modules))
    }

    /// Read the package bytes stored on-disk at `addr`
    fn get_package_bytes(
        &self,
        address: &AccountAddress,
    ) -> Result<Option<BTreeMap<Identifier, Vec<u8>>>> {
        let addr_path = self.get_package_path(address);
        self.get_package_bytes_at_path(&addr_path)
    }

    pub fn has_package(&self, package_id: &PackageStorageId) -> bool {
        self.get_package_path(package_id).exists()
    }

    /// Check if a module at `addr`/`module_id` exists
    pub fn has_module_in_package(
        &self,
        package_id: &PackageStorageId,
        module_name: &IdentStr,
    ) -> bool {
        self.get_module_path(package_id, module_name).exists()
    }

    /// Return the name of the function at `idx` in `module_id`
    pub fn resolve_function(
        &self,
        package_id: PackageStorageId,
        module_name: &IdentStr,
        idx: u16,
    ) -> Result<Option<Identifier>> {
        let module_id = ModuleId::new(package_id, module_name.to_owned());
        if let Some(m) = self.get_module_by_id(&module_id)? {
            Ok(Some(
                m.identifier_at(
                    m.function_handle_at(m.function_def_at(FunctionDefinitionIndex(idx)).function)
                        .name,
                )
                .to_owned(),
            ))
        } else {
            Ok(None)
        }
    }

    fn get_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
        Ok(if path.exists() {
            Some(fs::read(path)?)
        } else {
            None
        })
    }

    fn view_bytecode(path: &Path) -> Result<Option<String>> {
        if path.is_dir() {
            bail!("Bad bytecode path {:?}. Needed file, found directory", path)
        }

        Ok(match Self::get_bytes(path)? {
            Some(bytes) => {
                let module = CompiledModule::deserialize_with_defaults(&bytes)
                    .map_err(|e| anyhow!("Failure deserializing module: {:?}", e))?;
                // TODO: find or create source map and pass it to disassembler
                let d: Disassembler =
                    Disassembler::from_module(&module, Spanned::unsafe_no_loc(()).loc)?;
                Some(d.disassemble()?)
            }
            None => None,
        })
    }

    pub fn view_module(module_path: &Path) -> Result<Option<String>> {
        Self::view_bytecode(module_path)
    }

    /// Save `module` on disk under the path `module.address()`/`module.name()`
    fn save_module(
        &self,
        package_id: &PackageStorageId,
        module_name: &IdentStr,
        module_bytes: &[u8],
    ) -> Result<()> {
        let path = self.get_module_path(package_id, module_name);
        if !path.exists() {
            fs::create_dir_all(path.parent().unwrap())?
        }
        Ok(fs::write(path, module_bytes)?)
    }

    /// Save the YAML encoding `layout` on disk under `build_dir/layouts/id`.
    pub fn save_struct_layouts(&self, layouts: &str) -> Result<()> {
        let layouts_file = self.struct_layouts_file();
        if !layouts_file.exists() {
            fs::create_dir_all(layouts_file.parent().unwrap())?
        }
        Ok(fs::write(layouts_file, layouts)?)
    }

    /// Save all the modules in the local cache, re-generate mv_interfaces if required.
    pub fn save_package(
        &self,
        package_id: &PackageStorageId,
        modules: impl IntoIterator<Item = (Identifier, Vec<u8>)>,
    ) -> Result<()> {
        for (module_name, module_bytes) in modules {
            self.save_module(package_id, &module_name, &module_bytes)?;
        }
        Ok(())
    }

    fn iter_paths<F>(&self, f: F) -> impl Iterator<Item = PathBuf>
    where
        F: FnOnce(&Path) -> bool + Copy,
    {
        walkdir::WalkDir::new(&self.storage_dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
            .map(|e| e.path().to_path_buf())
            .filter(move |path| f(path))
    }

    pub fn package_paths(&self) -> impl Iterator<Item = PathBuf> + '_ {
        self.iter_paths(move |p| self.is_package_path(p))
    }

    /// Build all modules in the self.storage_dir.
    /// Returns an Err if a module does not deserialize.
    pub fn get_all_packages(
        &self,
    ) -> Result<BTreeMap<PackageStorageId, BTreeMap<Identifier, CompiledModule>>> {
        self.package_paths()
            .map(|path| {
                let package_id = self.storage_id_of_path(&path).unwrap();
                let modules = self
                    .get_package_bytes_at_path(&path)?
                    .unwrap()
                    .into_iter()
                    .map(|(mname, mbytes)| {
                        Ok((
                            mname,
                            CompiledModule::deserialize_with_defaults(&mbytes)
                                .map_err(|e| anyhow!("Failed to deserialized module: {:?}", e))?,
                        ))
                    })
                    .collect::<Result<_>>()?;
                Ok((package_id, modules))
            })
            .collect::<Result<_>>()
    }

    /// Get the compiled modules for a given package.
    pub fn get_compiled_modules(
        &self,
        package_address: &AccountAddress,
    ) -> Result<Vec<CompiledModule>> {
        let Some(package_bytes) = self.get_package_bytes(package_address)? else {
            return Err(anyhow!("No package fount at {package_address}"));
        };
        package_bytes
            .into_iter()
            .map(|(_, module)| {
                CompiledModule::deserialize_with_defaults(&module)
                    .map_err(|e| anyhow!("Failed to deserialized module: {:?}", e))
            })
            .collect::<Result<Vec<CompiledModule>>>()
    }

    /// Compute all of the transitive dependencies for a `root_package`, including itself.
    pub fn transitive_dependencies(
        &self,
        root_package: &AccountAddress,
    ) -> Result<BTreeSet<AccountAddress>> {
        let mut seen: BTreeSet<AccountAddress> = BTreeSet::new();
        let mut to_process: Vec<AccountAddress> = vec![*root_package];

        while let Some(package_id) = to_process.pop() {
            // If we've already processed this package, skip it
            if seen.contains(&package_id) {
                continue;
            }

            // Add the current package to the seen set
            seen.insert(package_id);

            // Attempt to retrieve the package's modules from the store
            let Ok(Some(modules)) = self.get_package(&package_id) else {
                return Err(anyhow!(
                    "Cannot find {:?} in data cache when building linkage context",
                    package_id
                ));
            };

            // Process each module and add its dependencies to the to_process list
            for module in &modules {
                let module = CompiledModule::deserialize_with_defaults(module).unwrap();
                let deps = module
                    .immediate_dependencies()
                    .into_iter()
                    .map(|module| *module.address());

                // Add unprocessed dependencies to the queue
                for dep in deps {
                    if !seen.contains(&dep) {
                        to_process.push(dep);
                    }
                }
            }
        }

        Ok(seen)
    }

    /// Generates a reflective link context (that is, all addresses map to themselves) by
    /// collecting the modules and transitive dependencies from the specified address.
    pub fn generate_linkage_context(
        &self,
        package_address: &AccountAddress,
    ) -> Result<LinkageContext> {
        let modules = self.get_compiled_modules(package_address)?;
        let mut all_dependencies: BTreeSet<AccountAddress> = BTreeSet::new();
        for module in modules {
            for dep in module
                .immediate_dependencies()
                .iter()
                .map(|dep| dep.address())
                .filter(|dep| *dep != package_address)
            {
                // If this dependency is in here, its transitive dependencies are, too.
                if all_dependencies.contains(dep) {
                    continue;
                }
                let new_dependencies = self.transitive_dependencies(dep)?;
                all_dependencies.extend(new_dependencies.into_iter());
            }
        }
        // Consider making tehse into VM errors on failure instead.
        assert!(
            !all_dependencies.remove(package_address),
            "Found circular dependencies during dependency generation."
        );
        let linkage_context = LinkageContext::new(
            *package_address,
            all_dependencies
                .into_iter()
                .map(|id| (id, id))
                .chain(vec![(*package_address, *package_address)])
                .collect(),
        );
        Ok(linkage_context)
    }
}

impl ModuleResolver for OnDiskStateView {
    type Error = anyhow::Error;
    fn get_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>, Self::Error> {
        let package = self.get_package_bytes(module_id.address())?;
        Ok(package.and_then(|modules| modules.get(module_id.name()).map(|bytes| bytes.clone())))
    }

    fn get_package(&self, id: &AccountAddress) -> Result<Option<Vec<Vec<u8>>>, Self::Error> {
        Ok(self
            .get_package_bytes(id)?
            .map(|modules| modules.into_iter().map(|(_, m)| m).collect()))
    }
}

impl ResourceResolver for OnDiskStateView {
    type Error = anyhow::Error;

    fn get_resource(
        &self,
        _address: &AccountAddress,
        _struct_tag: &StructTag,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        unimplemented!()
    }
}

impl Default for OnDiskStateView {
    fn default() -> Self {
        OnDiskStateView::create(Path::new(DEFAULT_BUILD_DIR), Path::new(DEFAULT_STORAGE_DIR))
            .expect("Failure creating OnDiskStateView")
    }
}
