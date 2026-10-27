/** What a connection can say about the state of its socket. */
export type Flow = {
  blocked(): boolean;
  onDrain(fn: () => void): void;
};

/**
 * One client connection, by identity. Runs belong to the connection that started them; handlers
 * compare connections with `===` and register cleanup with `onClose`.
 */
export class Connection {
  #closed = false;
  readonly #listeners: (() => void)[] = [];
  readonly #flow: Flow | undefined;

  constructor(flow?: Flow) {
    this.#flow = flow;
  }

  /** True while the peer is not reading what we send (the socket's write buffer is full). */
  get blocked(): boolean {
    return !this.#closed && (this.#flow?.blocked() ?? false);
  }

  /** Call `fn` once when the peer has caught up. Not called if the connection closes first. */
  onceDrained(fn: () => void): void {
    this.#flow?.onDrain(fn);
  }

  /** Run `fn` when the connection closes, or at once if it already has. Returns a way to unsubscribe. */
  onClose(fn: () => void): () => void {
    if (this.#closed) {
      fn();
      return () => {};
    }
    this.#listeners.push(fn);
    return () => {
      const i = this.#listeners.indexOf(fn);
      if (i !== -1) this.#listeners.splice(i, 1);
    };
  }

  /** Mark the connection closed and run the listeners. Safe to call twice. */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const fn of this.#listeners.splice(0)) {
      try {
        fn();
      } catch {
        // One faulty listener must not keep the others from running.
      }
    }
  }
}
