export function splitLines (str: string): string {
    if (str.length <= 60) {
        return str;
    }

    return str.slice(0, 60) + "\n" + splitLines(str.slice(60));
}