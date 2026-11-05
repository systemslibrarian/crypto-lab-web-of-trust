import { expect, it } from 'vitest';
import { LOG_LINE_CLASS, LOG_LINES_SHOWN, renderLogLines } from '../src/log-lines.ts';

interface StubLine {
    tag: string;
    className: string;
    textContent: string | null;
}

/**
 * A stub element factory and a host that REFUSES html. The host is a Proxy that throws
 * on any `innerHTML` assignment, so the shape CodeQL flagged cannot return quietly: a
 * renderer that writes markup fails here instead of passing with a different sink.
 */
function harness(): {
    host: { replaceChildren(...nodes: never[]): void };
    factory: { createElement(tag: 'p'): StubLine };
    received: () => StubLine[];
} {
    let received: StubLine[] = [];
    const bare = {
        replaceChildren(...nodes: never[]): void {
            received = nodes as unknown as StubLine[];
        },
    };
    const host = new Proxy(bare, {
        set(target, property, value) {
            if (property === 'innerHTML' || property === 'outerHTML') {
                throw new Error(`the scenario log assigned ${String(property)}`);
            }
            return Reflect.set(target, property, value);
        },
    });
    return {
        host,
        factory: {
            createElement: (tag: 'p'): StubLine => ({ tag, className: '', textContent: null }),
        },
        received: () => received,
    };
}

it('renders each log line as text, with markup left as characters', () => {
    const payload = '<img src=x onerror="document.title=\'xss\'">';
    const h = harness();
    renderLogLines(h.host, h.factory, [`[12:00:00] ${payload} self-revoked their key.`]);

    const lines = h.received();
    expect(lines).toHaveLength(1);
    expect(lines[0].tag).toBe('p');
    expect(lines[0].className).toBe(LOG_LINE_CLASS);
    // The payload survives as TEXT, character for character: that is the whole point.
    expect(lines[0].textContent).toBe(`[12:00:00] ${payload} self-revoked their key.`);
});

it('shows only the newest lines, and keeps their order', () => {
    const h = harness();
    const lines = Array.from({ length: LOG_LINES_SHOWN + 4 }, (_, i) => `line ${i}`);
    renderLogLines(h.host, h.factory, lines);

    const rendered = h.received();
    expect(rendered).toHaveLength(LOG_LINES_SHOWN);
    expect(rendered.map((l) => l.textContent)).toEqual(lines.slice(0, LOG_LINES_SHOWN));
});

it('replaces the previous lines rather than appending to them', () => {
    const h = harness();
    renderLogLines(h.host, h.factory, ['first']);
    renderLogLines(h.host, h.factory, ['second']);
    expect(h.received().map((l) => l.textContent)).toEqual(['second']);
});
