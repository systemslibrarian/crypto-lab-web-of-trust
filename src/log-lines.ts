/**
 * The scenario log, rendered as TEXT.
 *
 * `state.logScenario` used to write its lines with
 *
 *     log.innerHTML = logLines.slice(0, 8).map((l) => `<p class="wot-log-line">${l}</p>`).join('')
 *
 * and CodeQL flagged the round trip — js/xss-through-dom, high, src/ui.ts:1177,
 * raised 2026-10-28. Its codeFlow is sixteen steps, and the first one is the point:
 * `btn.dataset.name` is READ BACK off a button, interpolated into a sentence, pushed
 * onto `logLines`, and reinterpreted as HTML at the sink.
 *
 * Nothing a visitor types can get there today. Identity names come from a literal
 * array in `buildSampleNetwork` and from generated `Flood00`-style names, the page's
 * only text-free inputs are two `type="number"` policy fields, and a `data-name` that
 * is not an identity makes the operation fail before it logs anything. So this is
 * defence in depth — but the sink is one lab feature away from a named identity, and
 * a log that renders its own markup is the wrong thing to leave in a lab about who
 * signed what.
 *
 * The renderer takes its element factory as an argument so the node test can hand it
 * a stub and watch what it assigns. That is also why the host is an interface: the
 * test's host THROWS on any `innerHTML` assignment, so the old shape cannot come back
 * quietly.
 */

/** The minimum of an element this renderer writes into. */
export interface LogHost {
    replaceChildren(...nodes: never[]): void;
}

/** The minimum of a document this renderer creates lines with. */
export interface LogLineFactory {
    createElement(tag: 'p'): { className: string; textContent: string | null };
}

export const LOG_LINE_CLASS = 'wot-log-line';
export const LOG_LINES_SHOWN = 8;

export function renderLogLines(
    host: LogHost,
    factory: LogLineFactory,
    lines: readonly string[],
    shown: number = LOG_LINES_SHOWN,
): void {
    const nodes = lines.slice(0, shown).map((line) => {
        const paragraph = factory.createElement('p');
        paragraph.className = LOG_LINE_CLASS;
        paragraph.textContent = line;
        return paragraph;
    });
    host.replaceChildren(...(nodes as unknown as never[]));
}
