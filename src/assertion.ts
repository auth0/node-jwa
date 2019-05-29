import { KeyObject, createPublicKey } from 'crypto';

interface KeyObjectLike {
    type: typeof KeyObject.prototype.type;
    asymmetricKeyType: typeof KeyObject.prototype.asymmetricKeyType;
    export: typeof KeyObject.prototype.export;
}

const MSG_INVALID_SECRET = 'Secret must be a string or Buffer.';
const MSG_INVALID_VERIFIER_KEY = 'Key must be a string, a Buffer, or a KeyObject.';
const MSG_INVALID_SIGNER_KEY = 'Key must be a string, a Buffer, or a KeyObject';

// Note: KeyObjects and crypto.createPublicKey were introduced in Node v11.6.0
const supportsKeyObjects = typeof createPublicKey === 'function';

function isBuffer(obj: any): obj is Buffer | string {
    return Buffer.isBuffer(obj);
}

function isString(obj: any): obj is string {
    return typeof obj === 'string';
}

function isKeyObject(obj: any): obj is KeyObject {
    return obj instanceof KeyObject;
}

function isLikeKeyObject(key: any): key is KeyObjectLike {
    return (
        typeof key === 'object' &&
        typeof key.type === 'string' &&
        typeof key.export === 'function' && 
        (
            typeof key.asymmetricKeySize === 'number' ||
            typeof key.symmetricSize === 'number'
        )
    );
}

export function assertPublicKeyHasValidType(key: any) {
    if (isBuffer(key))
        return;

    if (isString(key))
        return;

    // Check if current node version supports KeyObjects
    if (!supportsKeyObjects)
        throw new TypeError(MSG_INVALID_VERIFIER_KEY);

    // If KeyObject's constructor is in the prototype chain, allow it
    if (isKeyObject(key))
        return;

    // Check likeness to KeyObject, useful if key was serialized
    if (isLikeKeyObject(key))
        return;

    throw new TypeError(MSG_INVALID_VERIFIER_KEY);
};

export function assertPrivateKeyHasValidType(key: any) {
    if (isBuffer(key))
        return;

    if (isString(key))
        return;

    if (typeof key === 'object')
        return;

    throw new TypeError(MSG_INVALID_SIGNER_KEY);
};

export function assertSecretKeyHasValidType(key: any) {
    if (Buffer.isBuffer(key))
        return;

    if (isString(key))
        return;

    if (!supportsKeyObjects)
        throw new TypeError(MSG_INVALID_SECRET);

    if (isKeyObject(key))
        return;

    if(isLikeKeyObject(key))
        return;

    if (key.type === 'secret')
        return;
    
    if (typeof key.export === 'function')
        return;

    throw new TypeError(MSG_INVALID_SECRET);
}


