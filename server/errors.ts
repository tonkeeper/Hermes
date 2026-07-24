/** An error carrying the HTTP status the relay should answer with. */
export class HttpError extends Error {
    constructor(readonly status: number, message: string) {
        super(message);
    }
}
