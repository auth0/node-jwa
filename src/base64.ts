export namespace Base64 {
    export function toBase64Url(base64: string): string {
        return base64
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
    }

    export function fromBase64Url(base64url: string): string {
        const padding = 4 - base64url.length % 4;
        if (padding !== 4) {
            for (let i = 0; i < padding; ++i) {
                base64url += '=';
            }
        }
        return base64url
            .replace(/\-/g, '+')
            .replace(/_/g, '/');
    }
}