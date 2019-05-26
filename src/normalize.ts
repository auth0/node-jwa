export function normalizeInput(input: any): string | Buffer {
    if (!(Buffer.isBuffer(input) || typeof input === 'string'))
        return JSON.stringify(input);
    return input;
}
