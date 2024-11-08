// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import type { AwsClientOptions } from './aws-client.js';
import type { AwsKmsSignerOptions } from './passkey-signer.js';
import { AwsKmsSigner } from './passkey-signer.js';

export { AwsKmsSigner };

export type { AwsKmsSignerOptions, AwsClientOptions };
