/** `daemon install` or `uninstall` cannot proceed; the message says what would make it work. */
export class ServiceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ServiceError";
  }
}
