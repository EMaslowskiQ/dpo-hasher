# Hasher Integration Guide

Reference documentation for integrating with the ref-hasher library.

---

## Quick Start

### Basic One-Shot Hashing

```typescript
import { Hasher, HashMethod } from 'ref-hasher';

// Static methods for simple use cases
const hash = await Hasher.sha256('hello world');
const blake3Hash = await Hasher.blake3(fileBuffer);

// Or use hashData with a method parameter
const hash = await Hasher.hashData(HashMethod.BLAKE3, data);
```

### Streaming (Large Files)

```typescript
import { Hasher, HashMethod } from 'ref-hasher';

const hasher = new Hasher(HashMethod.SHA256);
await hasher.open();

// Process file in chunks
for await (const chunk of readFileInChunks(filePath)) {
  hasher.update(chunk);
}

// Get final hash
const result = await hasher.digestAsync();
console.log(result.data.hash); // hex string
```

### Resumable Hashing (For Interrupted Operations)

```typescript
import { Hasher, HashMethod } from 'ref-hasher';

// Create hasher with resumable option to force WASM engine
const hasher = new Hasher(HashMethod.SHA256, { resumable: true });
await hasher.open();

// Process chunks...
hasher.update(chunk1);
hasher.update(chunk2);

// Save state for later
const snapshot = hasher.getStateSnapshot(bytesHashed, chunkIndex);
persistToDisk(snapshot.data);

// Later: restore and continue
const hasher2 = new Hasher(HashMethod.SHA256, { resumable: true });
await hasher2.open();
hasher2.load(savedSnapshot.state);
hasher2.update(chunk3); // Continue from where we left off
```

---

## Core Features

| Feature | Description | Default |
|---------|-------------|---------|
| **Hash Methods** | MD5, SHA-256, SHA-512, CRC32, CRC32C, BLAKE3 | BLAKE3 |
| **S3 Composite Checksums** | CRC32C composite format for S3 multipart uploads | Via `CRC32C_S3` |
| **Streaming** | Incremental hashing for large files | Supported |
| **Resumability** | Save/restore hash state mid-operation | Opt-in via `{ resumable: true }` |
| **Auto Engine Selection** | Uses fastest available engine per environment | Enabled |
| **Node Native Crypto** | Uses `node:crypto` for MD5/SHA-256/SHA-512 in Node.js | Enabled (non-resumable) |
| **Web Crypto API** | Uses `crypto.subtle` for SHA-256/SHA-512 in browsers | Enabled (non-resumable) |
| **WASM Fallback** | hash-wasm for all algorithms, all environments | Always available |

---

## Hash Methods

| Method | Use Case | Speed | Output Length |
|--------|----------|-------|---------------|
| `blake3` | Default, fast and secure | Fastest | 64 hex chars |
| `sha256` | Compatibility, widely supported | Fast | 64 hex chars |
| `sha512` | Higher security margin | Fast | 128 hex chars |
| `crc32` | Quick checksums (IEEE polynomial) | Very Fast | 8 hex chars |
| `crc32c` | iSCSI, ext4 (Castagnoli polynomial) | Very Fast | 8 hex chars |
| `crc32c-s3` | S3 multipart uploads (composite format) | Very Fast | base64 + part count |
| `md5` | Legacy compatibility only | Fast | 32 hex chars |

```typescript
import { HashMethod } from 'ref-hasher';

HashMethod.BLAKE3    // 'blake3'
HashMethod.SHA256    // 'sha256'
HashMethod.SHA512    // 'sha512'
HashMethod.CRC32     // 'crc32'
HashMethod.CRC32C    // 'crc32c'
HashMethod.CRC32C_S3 // 'crc32c-s3'
HashMethod.MD5       // 'md5'
```

---

## Engine Selection

The library automatically selects the best available hashing engine based on environment and options.

### Engine Priority

| Environment | Resumable | SHA-256/512 | MD5 | BLAKE3/CRC32/CRC32C |
|-------------|-----------|-------------|-----|---------------------|
| Node.js     | `false`   | node-native | node-native | wasm |
| Node.js     | `true`    | wasm | wasm | wasm |
| Browser     | `false`   | web-crypto | wasm | wasm |
| Browser     | `true`    | wasm | wasm | wasm |

> **Note:** CRC32C_S3 always uses WASM and is never resumable (it tracks per-chunk checksums, not streaming state).

### Checking the Engine

```typescript
const hasher = new Hasher(HashMethod.SHA256);
await hasher.open();

console.log(hasher.getEngine());     // 'node-native', 'web-crypto', or 'wasm'
console.log(hasher.isResumable());   // true only if engine is 'wasm'
```

### Forcing WASM for Resumability

```typescript
// Option 1: Use resumable option
const hasher = new Hasher(HashMethod.SHA256, { resumable: true });
await hasher.open();
console.log(hasher.getEngine());     // 'wasm'
console.log(hasher.isResumable());   // true

// Option 2: Use BLAKE3 or CRC32 (always WASM)
const hasher = new Hasher(HashMethod.BLAKE3);
await hasher.open();
console.log(hasher.isResumable());   // true (BLAKE3 always uses WASM)
```

---

## API Reference

### Constructor

```typescript
new Hasher(method?: HashMethod, options?: HasherOptions)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `method` | `HashMethod` | `'blake3'` | Hash algorithm to use |
| `options.resumable` | `boolean` | `false` | Force WASM engine for save/load support |

### Instance Methods

#### Lifecycle

| Method | Returns | Description |
|--------|---------|-------------|
| `open()` | `Promise<IOResult>` | Initialize the hasher engine |
| `init()` | `IOResult` | Reset state for reuse (after open) |
| `update(data)` | `IOResult` | Add data to hash |
| `digest()` | `IOResult` | Finalize and get hash (sync, throws for web-crypto) |
| `digestAsync()` | `Promise<IOResult>` | Finalize and get hash (async, works with all engines) |

#### State Management

| Method | Returns | Description |
|--------|---------|-------------|
| `save()` | `IOResult<{ state: string }>` | Save internal hasher state (base64) |
| `load(state)` | `IOResult` | Restore hasher state from base64 string |
| `getStateSnapshot(bytes, chunkIndex)` | `IOResult<HashStateSnapshot>` | Get full snapshot for persistence |

#### Inspection

| Method | Returns | Description |
|--------|---------|-------------|
| `getMethod()` | `HashMethod` | Get the hash method |
| `getEngine()` | `HashEngine` | Get the engine (`'wasm'`, `'node-native'`, `'web-crypto'`) |
| `isResumable()` | `boolean` | Check if save/load will work |

### Static Methods

```typescript
// One-shot hashing (auto-selects best engine)
Hasher.hashData(method: HashMethod, data: IDataType): Promise<string>
Hasher.md5(data: IDataType, limit?: number): Promise<string>
Hasher.sha256(data: IDataType, limit?: number): Promise<string>
Hasher.sha512(data: IDataType, limit?: number): Promise<string>
Hasher.crc32(data: IDataType, limit?: number): Promise<string>
Hasher.crc32c(data: IDataType, limit?: number): Promise<string>
Hasher.blake3(data: IDataType, limit?: number): Promise<string>

// S3-specific helpers
Hasher.crc32cBase64(data: IDataType): Promise<string>
Hasher.computeS3CompositeChecksum(partChecksums: string[]): Promise<string>
```

The `limit` parameter truncates the hash to the first N characters (useful for short IDs).

### Types

```typescript
interface IOResult<T> {
  success: boolean;
  message: string;
  data?: T;
}

interface HasherOptions {
  resumable?: boolean;  // Force WASM for save/load support
}

interface HashStateSnapshot {
  method: HashMethod | 'none';
  state: string;           // Base64-encoded hasher state
  bytesHashed: number;
  afterChunkIndex: number;
}

type HashEngine = 'wasm' | 'node-native' | 'web-crypto';
type HashMethod = 'md5' | 'sha256' | 'sha512' | 'crc32' | 'crc32c' | 'crc32c-s3' | 'blake3';

// IDataType from hash-wasm: string | ArrayBuffer | Uint8Array | Buffer
```

---

## Usage Patterns

### Pattern 1: Simple File Hash

```typescript
import { Hasher } from 'ref-hasher';
import { readFile } from 'fs/promises';

const buffer = await readFile('large-file.zip');
const hash = await Hasher.blake3(buffer);
console.log(hash); // '7d865e959b2466918c9863...'
```

### Pattern 2: Streaming Large Files

```typescript
import { Hasher, HashMethod } from 'ref-hasher';
import { createReadStream } from 'fs';

async function hashFile(filePath: string): Promise<string> {
  const hasher = new Hasher(HashMethod.BLAKE3);
  await hasher.open();

  const stream = createReadStream(filePath, { highWaterMark: 64 * 1024 });

  for await (const chunk of stream) {
    hasher.update(chunk);
  }

  const result = await hasher.digestAsync();
  if (!result.success) throw new Error(result.message);

  return result.data.hash;
}
```

### Pattern 3: Browser File Upload with Hash

```typescript
import { Hasher, HashMethod } from 'ref-hasher';

async function hashAndUpload(file: File): Promise<void> {
  const hasher = new Hasher(HashMethod.SHA256);
  await hasher.open();

  const chunkSize = 8 * 1024 * 1024; // 8 MB
  let offset = 0;

  while (offset < file.size) {
    const chunk = file.slice(offset, offset + chunkSize);
    const buffer = await chunk.arrayBuffer();
    hasher.update(new Uint8Array(buffer));
    offset += chunkSize;
  }

  const result = await hasher.digestAsync();
  const hash = result.data.hash;

  // Upload with hash for server-side verification
  await uploadFile(file, hash);
}
```

### Pattern 4: Resumable Upload with Hash Checkpoints

```typescript
import { Hasher, HashMethod, HashStateSnapshot } from 'ref-hasher';

interface UploadProgress {
  chunkIndex: number;
  bytesUploaded: number;
  hashSnapshot: HashStateSnapshot;
}

async function resumableUpload(
  file: File,
  savedProgress?: UploadProgress
): Promise<string> {
  // Must use resumable: true for save/load support
  const hasher = new Hasher(HashMethod.BLAKE3, { resumable: true });
  await hasher.open();

  let startChunk = 0;
  const chunkSize = 8 * 1024 * 1024;

  // Restore state if resuming
  if (savedProgress) {
    hasher.load(savedProgress.hashSnapshot.state);
    startChunk = savedProgress.chunkIndex + 1;
  }

  const totalChunks = Math.ceil(file.size / chunkSize);

  for (let i = startChunk; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, file.size);
    const chunk = await file.slice(start, end).arrayBuffer();

    hasher.update(new Uint8Array(chunk));
    await uploadChunk(chunk, i);

    // Save checkpoint every 10 chunks
    if (i % 10 === 0) {
      const snapshot = hasher.getStateSnapshot(end, i);
      if (snapshot.success) {
        saveProgress({ chunkIndex: i, bytesUploaded: end, hashSnapshot: snapshot.data });
      }
    }
  }

  const result = await hasher.digestAsync();
  return result.data.hash;
}
```

### Pattern 5: Reusing a Hasher Instance

```typescript
const hasher = new Hasher(HashMethod.SHA256);
await hasher.open();

// Hash first item
hasher.update(data1);
const hash1 = (await hasher.digestAsync()).data.hash;

// Reset and hash second item (reuses WASM instance)
hasher.init();
hasher.update(data2);
const hash2 = (await hasher.digestAsync()).data.hash;
```

### Pattern 6: S3 Multipart Upload with Composite Checksum

```typescript
import { Hasher, HashMethod } from 'ref-hasher';

// Method 1: Using CRC32C_S3 streaming mode
async function uploadWithS3Checksum(file: File, uploadPart: Function) {
  const hasher = new Hasher(HashMethod.CRC32C_S3);
  await hasher.open();

  const chunkSize = 8 * 1024 * 1024; // 8 MB
  let partNumber = 1;

  for (let offset = 0; offset < file.size; offset += chunkSize) {
    const chunk = await file.slice(offset, offset + chunkSize).arrayBuffer();
    const data = new Uint8Array(chunk);

    // Each update() computes per-chunk CRC32C internally
    hasher.update(data);

    // Get the per-chunk checksum for S3 ChecksumCRC32C header
    const chunkChecksum = await Hasher.crc32cBase64(data);
    await uploadPart(partNumber++, data, chunkChecksum);
  }

  // digest() returns S3 composite format: "base64checksum-partCount"
  const result = hasher.digest();
  return result.data.hash; // e.g., "gVZk2w==-5"
}

// Method 2: Using static helper with pre-computed checksums
async function computeCompositeFromParts(partChecksums: string[]) {
  // partChecksums is an array of base64-encoded CRC32C values
  const composite = await Hasher.computeS3CompositeChecksum(partChecksums);
  return composite; // e.g., "gVZk2w==-5"
}
```

**S3 Composite Format:**
- Each part has its own CRC32C checksum (base64-encoded 4 bytes)
- Final checksum: `base64(CRC32C(part1_crc || part2_crc || ...)) + "-" + partCount`
- Example: `"gVZk2w==-5"` means composite checksum `gVZk2w==` from 5 parts

**Important:** `CRC32C_S3` is NOT resumable. It tracks per-chunk checksums, not streaming hash state.

---

## Environment Considerations

### Node.js

- **Native crypto** is used for MD5, SHA-256, SHA-512 by default
- Native crypto is ~2-3x faster than WASM for large files
- Use `{ resumable: true }` if you need to save/restore state

```typescript
// Fast path (native crypto)
const hasher = new Hasher(HashMethod.SHA256);

// Resumable path (WASM)
const hasher = new Hasher(HashMethod.SHA256, { resumable: true });
```

### Browser (Vite, Webpack, etc.)

- **Web Crypto API** is used for SHA-256, SHA-512 by default
- Web Crypto is hardware-accelerated in most browsers
- MD5, BLAKE3, CRC32 always use WASM
- The `node:crypto` import is wrapped in environment checks and won't break bundlers

```typescript
// In browser: uses crypto.subtle for SHA-256
const hash = await Hasher.sha256(data);

// In browser: uses WASM for BLAKE3
const hash = await Hasher.blake3(data);
```

### Web Crypto Limitation

Web Crypto's `digest()` is async-only. Use `digestAsync()` for consistent behavior:

```typescript
// This throws in browser with web-crypto engine
hasher.digest(); // Error: Use digestAsync()

// This works everywhere
await hasher.digestAsync(); // OK
```

---

## Resumability

### When to Use Resumable Mode

| Scenario | Resumable | Why |
|----------|-----------|-----|
| Small file, one-shot | No | No benefit, adds overhead |
| Large file, reliable connection | No | Performance > resume capability |
| Large file, unreliable connection | Yes | Resume after network failures |
| Upload with checkpoints | Yes | Save state at intervals |
| Background processing | Yes | Survive process restarts |

### Resumability by Engine

| Engine | Resumable | Notes |
|--------|-----------|-------|
| `wasm` | Yes | Full save/load support |
| `node-native` | No | Node crypto doesn't expose internal state |
| `web-crypto` | No | Web Crypto doesn't expose internal state |

### Non-Resumable Methods

| Method | Reason |
|--------|--------|
| `CRC32C_S3` | Tracks per-chunk checksums, not streaming state |

> **Note:** Even with `{ resumable: true }`, CRC32C_S3 cannot be resumed because it doesn't maintain a streaming hash state.

### HashStateSnapshot Structure

```typescript
interface HashStateSnapshot {
  method: HashMethod | 'none';  // e.g., 'blake3'
  state: string;                 // Base64-encoded internal hasher state
  bytesHashed: number;           // Total bytes hashed so far
  afterChunkIndex: number;       // Chunk index when snapshot was taken
}
```

### Save/Load Example

```typescript
// Save
const hasher = new Hasher(HashMethod.SHA256, { resumable: true });
await hasher.open();
hasher.update(chunk1);
hasher.update(chunk2);

const saveResult = hasher.save();
if (saveResult.success) {
  const base64State = saveResult.data.state;
  // Persist base64State to disk/database
}

// Load (later, possibly after restart)
const hasher2 = new Hasher(HashMethod.SHA256, { resumable: true });
await hasher2.open();
hasher2.load(base64State);

// Continue hashing
hasher2.update(chunk3);
const finalHash = await hasher2.digestAsync();
```

---

## S3 Checksums

Amazon S3 uses CRC32C (Castagnoli polynomial) for integrity verification with a specific composite format for multipart uploads.

### Understanding S3 Composite Checksums

Unlike streaming hashes, S3's multipart checksum works differently:

1. **Per-part checksum:** Each part has its own CRC32C (base64-encoded 4 bytes)
2. **Composite checksum:** `base64(CRC32C(part1_crc || part2_crc || ...)) + "-" + partCount`
3. **Example:** `"gVZk2w==-5"` = composite checksum `gVZk2w==` computed from 5 parts

### Available S3 Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| `HashMethod.CRC32C_S3` | Streaming mode that tracks per-chunk CRC32C | Full file upload with integrity |
| `Hasher.crc32cBase64(data)` | One-shot CRC32C returning base64 | Per-part checksum for S3 header |
| `Hasher.computeS3CompositeChecksum(parts)` | Compute composite from checksums array | Verify/compute composite externally |

### CRC32C_S3 Streaming Mode

```typescript
const hasher = new Hasher(HashMethod.CRC32C_S3);
await hasher.open();

// Each update() computes and stores per-chunk CRC32C
hasher.update(chunk1);  // Stores base64 CRC32C for chunk 1
hasher.update(chunk2);  // Stores base64 CRC32C for chunk 2
hasher.update(chunk3);  // Stores base64 CRC32C for chunk 3

// digest() computes composite from all stored checksums
const result = hasher.digest();
console.log(result.data.hash);       // "gVZk2w==-3"
console.log(result.data.partsCount); // 3
```

### Per-Part Checksum for S3 Headers

When uploading parts to S3, include the `ChecksumCRC32C` header:

```typescript
// Compute base64-encoded CRC32C for the S3 header
const checksum = await Hasher.crc32cBase64(partData);

// Use in S3 UploadPart request
await s3.send(new UploadPartCommand({
  // ... other params
  ChecksumCRC32C: checksum,  // e.g., "gVZk2w=="
}));
```

### Computing Composite from Existing Checksums

If you already have per-part checksums (e.g., from S3 responses):

```typescript
const partChecksums = [
  "abc123==",  // Part 1 CRC32C
  "def456==",  // Part 2 CRC32C
  "ghi789==",  // Part 3 CRC32C
];

const composite = await Hasher.computeS3CompositeChecksum(partChecksums);
// Returns: "xyz000==-3"
```

### S3 Limitations

| Limitation | Description |
|------------|-------------|
| **Not resumable** | CRC32C_S3 tracks per-chunk checksums, not streaming state |
| **No one-shot mode** | `hashData(CRC32C_S3, data)` throws an error |
| **Chunk = Part** | Each `update()` call = one S3 part |

### Complete S3 Upload Example

```typescript
import { Hasher, HashMethod } from 'ref-hasher';
import { S3Client, CreateMultipartUploadCommand, UploadPartCommand, CompleteMultipartUploadCommand } from '@aws-sdk/client-s3';

async function uploadToS3WithIntegrity(file: File, bucket: string, key: string) {
  const s3 = new S3Client({ region: 'us-east-1' });
  const chunkSize = 8 * 1024 * 1024; // 8 MB minimum for S3 multipart

  // Create multipart upload
  const { UploadId } = await s3.send(new CreateMultipartUploadCommand({
    Bucket: bucket,
    Key: key,
    ChecksumAlgorithm: 'CRC32C',
  }));

  // Track checksums for composite
  const hasher = new Hasher(HashMethod.CRC32C_S3);
  await hasher.open();

  const parts = [];
  let partNumber = 1;

  for (let offset = 0; offset < file.size; offset += chunkSize) {
    const chunk = await file.slice(offset, offset + chunkSize).arrayBuffer();
    const data = new Uint8Array(chunk);

    // Track for composite calculation
    hasher.update(data);

    // Get per-part checksum for S3 header
    const partChecksum = await Hasher.crc32cBase64(data);

    // Upload part with checksum
    const { ETag, ChecksumCRC32C } = await s3.send(new UploadPartCommand({
      Bucket: bucket,
      Key: key,
      UploadId,
      PartNumber: partNumber,
      Body: data,
      ChecksumCRC32C: partChecksum,
    }));

    parts.push({ PartNumber: partNumber, ETag, ChecksumCRC32C });
    partNumber++;
  }

  // Get our computed composite
  const digestResult = hasher.digest();
  const ourComposite = digestResult.data.hash;

  // Complete multipart upload
  const { ChecksumCRC32C: s3Composite } = await s3.send(new CompleteMultipartUploadCommand({
    Bucket: bucket,
    Key: key,
    UploadId,
    MultipartUpload: { Parts: parts },
  }));

  // Verify integrity
  if (ourComposite !== s3Composite) {
    throw new Error(`Checksum mismatch: local=${ourComposite}, s3=${s3Composite}`);
  }

  return { key, checksum: s3Composite };
}
```

---

## IOResult Pattern

All methods return an `IOResult<T>` object for consistent error handling:

```typescript
interface IOResult<T> {
  success: boolean;
  message: string;
  data?: T;
}
```

### Handling Results

```typescript
const result = await hasher.digestAsync();

if (result.success) {
  console.log('Hash:', result.data.hash);
  console.log('Time:', result.data.timeElapsed, 'ms');
} else {
  console.error('Error:', result.message);
}
```

### Chaining Operations

```typescript
const openResult = await hasher.open();
if (!openResult.success) throw new Error(openResult.message);

const updateResult = hasher.update(data);
if (!updateResult.success) throw new Error(updateResult.message);

const digestResult = await hasher.digestAsync();
if (!digestResult.success) throw new Error(digestResult.message);

return digestResult.data.hash;
```

---

## Common Pitfalls

### Using digest() with Web Crypto

**Symptoms:**
- Error: "Web Crypto requires async digest. Use digestAsync() instead."

**Cause:** The synchronous `digest()` method cannot work with the async-only Web Crypto API.

**Solution:** Always use `digestAsync()` for cross-platform compatibility:

```typescript
// Bad: May throw in browser
const result = hasher.digest();

// Good: Works everywhere
const result = await hasher.digestAsync();
```

---

### Save/Load Fails with Native Engine

**Symptoms:**
- Error: "Cannot save state with node-native engine. Create hasher with { resumable: true } option."

**Cause:** Native crypto engines don't support state serialization.

**Solution:** Create the hasher with `resumable: true`:

```typescript
// Bad: Uses native engine, can't save
const hasher = new Hasher(HashMethod.SHA256);
await hasher.open();
hasher.save(); // Error!

// Good: Forces WASM engine
const hasher = new Hasher(HashMethod.SHA256, { resumable: true });
await hasher.open();
hasher.save(); // OK
```

---

### Forgetting to Call open()

**Symptoms:**
- Error: "no hasher created. initialize first."

**Cause:** The hasher engine must be initialized before use.

**Solution:** Always call `open()` after construction:

```typescript
const hasher = new Hasher(HashMethod.SHA256);
await hasher.open();  // Don't forget this!
hasher.update(data);
```

---

### Hash Mismatch After Resume

**Symptoms:**
- Final hash doesn't match expected value
- Data integrity check fails

**Cause:** Hash state wasn't properly restored, or chunks were re-hashed.

**Solution:** Ensure you restore state AND skip already-hashed chunks:

```typescript
// Wrong: Re-hashing from beginning
hasher.load(savedState);
for (const chunk of allChunks) {  // Re-hashing all chunks!
  hasher.update(chunk);
}

// Correct: Skip already-hashed chunks
hasher.load(savedState);
const startIndex = savedSnapshot.afterChunkIndex + 1;
for (let i = startIndex; i < allChunks.length; i++) {
  hasher.update(allChunks[i]);
}
```

---

### Different Hash on Same Data

**Symptoms:**
- Same file produces different hashes

**Possible Causes:**

| Cause | Solution |
|-------|----------|
| Different encoding | Ensure consistent string encoding (UTF-8) |
| Partial data | Verify all data is being hashed |
| Different methods | Check `HashMethod` is consistent |
| Truncation via `limit` | Don't use `limit` for verification |

---

### Performance Issues in Browser

**Symptoms:**
- Hashing is slower than expected in browser

**Possible Causes:**

| Cause | Solution |
|-------|----------|
| Using BLAKE3 for large files | WASM is slower than native; use SHA-256 |
| Using `{ resumable: true }` | Forces WASM; only use when needed |
| Small chunk sizes | Use larger chunks (8MB+) to reduce overhead |

**Recommendations:**
- For non-resumable browser hashing, use SHA-256 or SHA-512 (Web Crypto)
- For resumable browser hashing, accept WASM performance or use BLAKE3 (optimized WASM)

---

### Using CRC32C_S3 Incorrectly

**Symptoms:**
- Error: "CRC32C_S3 requires streaming mode (open/update/digest)"
- Error: "Cannot save state with wasm engine" (for S3 mode)

**Cause:** CRC32C_S3 doesn't support one-shot hashing or resumability.

**Solution:** Use streaming mode and don't attempt to save/load state:

```typescript
// Wrong: One-shot doesn't work for S3
await Hasher.hashData(HashMethod.CRC32C_S3, data); // Error!

// Wrong: Can't save/load S3 state
const hasher = new Hasher(HashMethod.CRC32C_S3);
await hasher.open();
hasher.update(data);
hasher.save(); // Error!

// Correct: Use streaming mode
const hasher = new Hasher(HashMethod.CRC32C_S3);
await hasher.open();
hasher.update(chunk1);
hasher.update(chunk2);
const result = hasher.digest(); // Returns composite checksum
```

---

### Mismatched S3 Composite Checksum

**Symptoms:**
- S3 CompleteMultipartUpload returns different checksum than computed locally

**Possible Causes:**

| Cause | Solution |
|-------|----------|
| Different chunk sizes | Ensure chunk boundaries match S3 part boundaries |
| Missed chunks | Verify every part was included in both calculations |
| Wrong order | Checksums must be in part number order |

**Debugging:**

```typescript
// Log each part's checksum to compare
for (let i = 0; i < chunks.length; i++) {
  const checksum = await Hasher.crc32cBase64(chunks[i]);
  console.log(`Part ${i + 1}: ${checksum}`);
}
```

---

## Performance Comparison

Approximate relative performance (higher = faster):

| Method | Node Native | Web Crypto | WASM |
|--------|-------------|------------|------|
| SHA-256 | 100% | 95% | 40% |
| SHA-512 | 100% | 95% | 35% |
| MD5 | 100% | N/A | 50% |
| BLAKE3 | N/A | N/A | 100% |
| CRC32 | N/A | N/A | 100% |
| CRC32C | N/A | N/A | 100% |
| CRC32C_S3 | N/A | N/A | 100% |

**Notes:**
- BLAKE3 WASM is highly optimized and often faster than SHA-256 WASM
- CRC32/CRC32C are very fast due to simple algorithm and small output
- For maximum performance without resumability: SHA-256 (native/web-crypto)
- For maximum performance with resumability: BLAKE3 (optimized WASM)
- For S3 multipart uploads: CRC32C_S3 is required for composite checksums
