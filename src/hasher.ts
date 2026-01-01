// client/src/core/util/hasher.ts

/**
 * Simple wrapper for hashing behavior. Currently supports a streamed approach
 * allowing for reuse of a single instance calling 'init' between uses, or
 * static one off approaches for smaller data.
 * 
 * ENVIRONMENT BEHAVIOR:
 * - Browser: Uses 'hash-wasm' for all algorithms.
 * - Node.js: Uses native 'node:crypto' for SHA256/SHA512/MD5 (speed) and 'hash-wasm' for BLAKE3/CRC32 (compatibility).
 * 
 * NOTE ON RESUMABILITY:
 * Native Node.js crypto does NOT support state serialization (save/load). 
 * If you require resumable hashing (pausing midway and saving state to disk), 
 * you must force the use of WASM or accept that save() will fail on native methods.
 *
 * Using the 'hash-wasm' library for Node and Browser hashing algorithms.
 * Dependencies: 0
 * Source: https://www.npmjs.com/package/hash-wasm
 *
 * Adapted from server/src/transfer-engine/core/util/hasher.ts for client parity.
 */
import { 
    md5, crc32, sha256, sha512, blake3, 
    createMD5, createCRC32, createSHA256, createSHA512, createBLAKE3 
} from 'hash-wasm';
import type { IHasher, IDataType } from 'hash-wasm';

//#region TYPES

export interface IOResult<T> {
    success: boolean;
    message: string;
    data?: T;
}

export const HashMethod = {
    MD5: 'md5',
    SHA256: 'sha256',
    SHA512: 'sha512',
    CRC32: 'crc32',
    BLAKE3: 'blake3',
} as const;

export type HashMethod = typeof HashMethod[keyof typeof HashMethod];

/** Hash state snapshot for resume support. */
export interface HashStateSnapshot {
    /** Hash method used. */
    method: HashMethod | 'none';
    /** Base64-encoded internal hasher state from hash-wasm save(). */
    state: string;
    /** Number of bytes that have been hashed. */
    bytesHashed: number;
    /** Chunk index after which this snapshot was taken. */
    afterChunkIndex: number;
}

//#endregion

//#region HELPERS

// Environment check
const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;

function getErrorString(error: unknown): string {
    if (error instanceof Error) {
        return error.message;
    }
    return String(error);
}

/** Convert Uint8Array to base64 string (browser-compatible). */
function uint8ArrayToBase64(bytes: Uint8Array): string {
    if (isNode) {
        return Buffer.from(bytes).toString('base64');
    }
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/** Convert base64 string to Uint8Array (browser-compatible). */
function base64ToUint8Array(base64: string): Uint8Array {
    if (isNode) {
        return new Uint8Array(Buffer.from(base64, 'base64'));
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Adapter to make Node's native crypto look like hash-wasm IHasher.
 * Note: Does not support save/load/blockSize.
 */
class NativeHasherAdapter implements IHasher {
    private engine: any;
    private cryptoLib: any;

    constructor(private algo: string, cryptoLib: any) {
        this.cryptoLib = cryptoLib;
        this.init();
    }

    init(): this {
        this.engine = this.cryptoLib.createHash(this.algo);
        return this;
    }

    update(data: IDataType): this {
        this.engine.update(data);
        return this;
    }

    digest(format: 'hex' | 'binary' = 'hex'): any {
        if (format === 'binary') {
            return new Uint8Array(this.engine.digest());
        }
        return this.engine.digest('hex');
    }

    save(): Uint8Array {
        throw new Error('Native crypto does not support state saving (resumability).');
    }

    load(state: any): this {
        throw new Error('Native crypto does not support state loading (resumability).');
    }
    
    blockSize = 0; 
    digestSize = 0; 
}

//#endregion

//#region HASHER CLASS

export class Hasher {
    public hash: string = '';
    public timeElapsed: number = 0;

    private method: HashMethod = HashMethod.BLAKE3;
    private hasher: IHasher | null = null;
    private timeStart: number = 0;
    private isUsingNative: boolean = false;

    constructor(method?: HashMethod) {
        this.method = method ?? this.method;
    }

    // streaming
    async open(): Promise<IOResult<unknown>> {
        try {
            this.hasher = null;
            this.isUsingNative = false;

            // 1. Attempt Native Node Crypto first for supported algorithms
            // Node Native supports SHA256, SHA512, MD5. 
            // It does NOT support BLAKE3 or CRC32 out of the box.
            const nativeSupported: HashMethod[] = [HashMethod.SHA256, HashMethod.SHA512, HashMethod.MD5];
            
            if (isNode && nativeSupported.includes(this.method)) {
                try {
                    // Dynamic import to avoid browser bundle issues
                    const crypto = await import('node:crypto');
                    this.hasher = new NativeHasherAdapter(this.method, crypto);
                    this.isUsingNative = true;
                } catch (e) {
                    console.warn('Failed to load native crypto, falling back to WASM', e);
                }
            }

            // 2. Fallback to WASM if native wasn't used or failed
            if (!this.hasher) {
                switch(this.method) {
                    case HashMethod.SHA256: {
                        this.hasher = await createSHA256();
                    } break;
                    
                    case HashMethod.SHA512: {
                        this.hasher = await createSHA512();
                    } break;
    
                    case HashMethod.BLAKE3: {
                        this.hasher = await createBLAKE3();
                    } break;
    
                    case HashMethod.CRC32: {
                        this.hasher = await createCRC32();
                    } break;
    
                    case HashMethod.MD5: {
                        this.hasher = await createMD5();
                    } break;
                }
            }

            if (!this.hasher) {
                throw new Error('Failed to create hasher instance.');
            }

            // initialize
            this.init();

            return { 
                success: true, 
                message: 'hash open success', 
                data: { 
                    method: this.method, 
                    engine: this.isUsingNative ? 'native-node' : 'wasm' 
                }
            };
        } catch(error) {
            return { success: false, message: 'hash open failed', data: { error: getErrorString(error), method: this.method }};
        }
    }

    init(): IOResult<unknown> {
        try {
            if(!this.hasher)
                throw new Error('no hasher created. initialize first.');

            this.hash = '';
            this.hasher.init();
            this.timeElapsed = 0;
            this.timeStart = Date.now();

            return { success: true, message: 'hash init success', data: { method: this.method }};
        } catch(error) {
            return { success: false, message: 'hash init failed', data: { error: getErrorString(error) }};
        }
    }

    update(data: IDataType): IOResult<unknown> {
        try {
            if(!this.hasher)
                throw new Error('no hasher created. initialize first.');

            this.hasher.update(data);
            return { success: true, message: 'hash update success', data: { method: this.method, size: data.length }};
        } catch(error) {
            return { success: false, message: 'hash update failed', data: { error: getErrorString(error) }};
        }
    }

    digest(): IOResult<unknown> {
        try {
            if(!this.hasher)
                throw new Error('no hasher created. initialize first.');

            this.hash = this.hasher.digest('hex');
            this.timeElapsed = Date.now() - this.timeStart;

            return { success: true, message: 'hash digest success', data: { method: this.method, hash: this.hash, timeElapsed: this.timeElapsed }};
        } catch(error) {
            return { success: false, message: 'hash digest failed', data: { error: getErrorString(error) }};
        }
    }

    /** Returns the hash method. */
    getMethod(): HashMethod {
        return this.method;
    }

    /** 
     * Save the current internal hash state for later resumption. 
     * WARNING: Fails if using Native Node Crypto.
     */
    save(): IOResult<{ state: string }> {
        try {
            if (!this.hasher)
                throw new Error('no hasher created. initialize first.');

            if (this.isUsingNative) {
                throw new Error('Cannot save state when using native Node crypto. Use WASM for resumable hashing.');
            }

            const stateBytes = this.hasher.save();
            const base64State = uint8ArrayToBase64(stateBytes);

            return { success: true, message: 'hash state saved', data: { state: base64State } };
        } catch (error) {
            return { success: false, message: 'hash save failed', data: { error: getErrorString(error) } as unknown as { state: string } };
        }
    }

    /** 
     * Restore hash state from a previously saved base64-encoded state.
     * WARNING: Fails if using Native Node Crypto.
     */
    load(base64State: string): IOResult<unknown> {
        try {
            if (!this.hasher)
                throw new Error('no hasher created. initialize first.');

            if (this.isUsingNative) {
                throw new Error('Cannot load state when using native Node crypto.');
            }

            const stateBytes = base64ToUint8Array(base64State);
            this.hasher.load(stateBytes);

            return { success: true, message: 'hash state loaded', data: { method: this.method } };
        } catch (error) {
            return { success: false, message: 'hash load failed', data: { error: getErrorString(error) } };
        }
    }

    /** Get current hash state snapshot for persistence. */
    getStateSnapshot(bytesHashed: number, afterChunkIndex: number): IOResult<HashStateSnapshot> {
        const saveResult = this.save();
        if (!saveResult.success || !saveResult.data) {
            return { success: false, message: saveResult.message };
        }

        const snapshot: HashStateSnapshot = {
            method: this.method,
            state: saveResult.data.state,
            bytesHashed,
            afterChunkIndex,
        };

        return { success: true, message: 'snapshot created', data: snapshot };
    }

    // static one-offs
    static async hashData(method: HashMethod, data: IDataType): Promise<string> {
        switch(method) {
            case HashMethod.SHA256:
                return Hasher.sha256(data);

            case HashMethod.SHA512:
                return Hasher.sha512(data);

            case HashMethod.BLAKE3:
                return Hasher.blake3(data);

            case HashMethod.CRC32:
                return Hasher.crc32(data);

            case HashMethod.MD5:
                return Hasher.md5(data);
        }
    }

    static async md5(data: IDataType, limit: number = 0): Promise<string> {
        let result: string;
        
        if (isNode) {
            const crypto = await import('node:crypto');
            const hash = crypto.createHash('md5');
            hash.update(data as any);
            result = hash.digest('hex');
        } else {
            result = await md5(data);
        }

        if(limit > 0) return result.substring(0, limit);
        return result;
    }

    static async crc32(data: IDataType, limit: number = 0): Promise<string> {
        const result: string = await crc32(data);
        if(limit > 0) return result.substring(0, limit);
        return result;
    }

    static async sha256(data: IDataType, limit: number = 0): Promise<string> {
        let result: string;

        if (isNode) {
            const crypto = await import('node:crypto');
            const hash = crypto.createHash('sha256');
            hash.update(data as any);
            result = hash.digest('hex');
        } else {
            result = await sha256(data);
        }

        if(limit > 0) return result.substring(0, limit);
        return result;
    }

    static async sha512(data: IDataType, limit: number = 0): Promise<string> {
        let result: string;

        if (isNode) {
            const crypto = await import('node:crypto');
            const hash = crypto.createHash('sha512');
            hash.update(data as any);
            result = hash.digest('hex');
        } else {
            result = await sha512(data);
        }

        if(limit > 0) return result.substring(0, limit);
        return result;
    }

    static async blake3(data: IDataType, limit: number = 0): Promise<string> {
        const result: string = await blake3(data);
        if(limit > 0) return result.substring(0, limit);
        return result;
    }
}

//#endregion