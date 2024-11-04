---
title: Module `0x2::attestation`
---



-  [Function `nitro_attestation_verify`](#0x2_attestation_nitro_attestation_verify)


<pre><code></code></pre>



<a name="0x2_attestation_nitro_attestation_verify"></a>

## Function `nitro_attestation_verify`

@param attestation: attesttaion documents bytes data.
@param enclave_pk: public key from enclave

If the attestation verifies against the pcrs and against the root of trust, also the user_data equals to attestation document's user data, return yes.


<pre><code><b>public</b> <b>fun</b> <a href="attestation.md#0x2_attestation_nitro_attestation_verify">nitro_attestation_verify</a>(<a href="attestation.md#0x2_attestation">attestation</a>: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, enclave_pk: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, pcr0: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, pcr1: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, pcr2: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>native</b> <b>fun</b> <a href="attestation.md#0x2_attestation_nitro_attestation_verify">nitro_attestation_verify</a>(
    <a href="attestation.md#0x2_attestation">attestation</a>: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    enclave_pk: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    pcr0: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    pcr1: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    pcr2: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
): bool;
</code></pre>



</details>
