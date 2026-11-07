// Named globals left by browser drivers. Only the short labels below leave the
// browser, and only when a match is found.
const MARKERS: Array<[RegExp, string]> = [
  [/^\$?cdc_|^\$wdc_/, 'chromedriver'],
  [/^__(webdriver|driver|selenium|fxdriver)_|^_Selenium_IDE|^_selenium$|^__selenium/, 'selenium'],
  [/^__playwright|^__pw_|^__pwInitScripts/, 'playwright'],
  [/^__puppeteer|^puppeteer_/, 'puppeteer'],
  [/^callPhantom$|^_phantom$/, 'phantomjs'],
  [/^__nightmare$/, 'nightmare'],
  [/^domAutomation/, 'dom-automation'],
];

export function scanArtefacts(): string[] {
  const found = new Set<string>();
  const names: string[] = [];
  try {
    names.push(...Object.getOwnPropertyNames(window), ...Object.getOwnPropertyNames(document));
  } catch {
    return [];
  }
  for (const name of names) {
    for (const [re, label] of MARKERS) {
      if (re.test(name)) found.add(label);
    }
  }
  return [...found];
}
