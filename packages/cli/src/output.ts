/** Write a line to stdout. */
export const say = (line = ""): void => void process.stdout.write(`${line}\n`);

/** Write a line to stderr. */
export const warn = (line: string): void => void process.stderr.write(`${line}\n`);

/** Aligned columns, two spaces apart. The last column is not padded. */
export function table(rows: string[][]): string[] {
  const widths: number[] = [];
  for (const row of rows) {
    row.forEach((cell, i) => {
      widths[i] = Math.max(widths[i] ?? 0, cell.length);
    });
  }
  return rows.map((row) =>
    row
      .map((cell, i) => (i === row.length - 1 ? cell : cell.padEnd(widths[i] ?? 0)))
      .join("  ")
      .trimEnd(),
  );
}

export const storedLine = (m: { name: string; type: string; length: number }): string =>
  `stored ${m.name} · ${m.type} · ${m.length} chars`;
