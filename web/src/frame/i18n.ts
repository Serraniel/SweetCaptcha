const en = {
  verifying: 'Verifying you are human',
  working: 'Checking your browser',
  checkbox: 'Verify you are human',
  checkboxPrompt: 'Please tick the box to continue',
  close: 'Close',
  verified: 'Verified',
  failed: 'Verification failed',
  retry: 'Try again',
  denied: 'We could not verify this browser.',
  contact: 'Contact support',
  brand: 'SweetCaptcha',
  puzzleTitle: 'One more step',
  lineTrace: 'Follow the lines from the circle and the square to their numbers on the right. Lines continue straight through crossings.',
  lineCircle: 'The line from the circle ends at:',
  lineSquare: 'The line from the square ends at:',
  gapRings: 'Select every ring that has a gap.',
  cell: 'Cell',
  rotate: 'Turn each right-hand shape until it matches the shape to its left.',
  rotateLabel: 'Rotation of shape',
  submit: 'Submit',
  waitOffer: "I can't do this task",
  waitNote: 'Your device runs a longer calculation instead. This can take a few minutes.',
  waiting: 'Calculating. You can leave this open.',
  wrong: 'That was not right. Here is a new one.',
};

const de: typeof en = {
  verifying: 'Überprüfung läuft',
  working: 'Browser wird geprüft',
  checkbox: 'Bestätige, dass du ein Mensch bist',
  checkboxPrompt: 'Bitte setze den Haken, um fortzufahren',
  close: 'Schließen',
  verified: 'Verifiziert',
  failed: 'Überprüfung fehlgeschlagen',
  retry: 'Erneut versuchen',
  denied: 'Dieser Browser konnte nicht verifiziert werden.',
  contact: 'Support kontaktieren',
  brand: 'SweetCaptcha',
  puzzleTitle: 'Noch ein Schritt',
  lineTrace: 'Folge den Linien vom Kreis und vom Quadrat bis zu ihren Zahlen rechts. An Kreuzungen laufen die Linien gerade weiter.',
  lineCircle: 'Die Linie vom Kreis endet bei:',
  lineSquare: 'Die Linie vom Quadrat endet bei:',
  gapRings: 'Wähle jeden Ring aus, der eine Lücke hat.',
  cell: 'Feld',
  rotate: 'Drehe jede rechte Form, bis sie zur linken Form passt.',
  rotateLabel: 'Drehung der Form',
  submit: 'Absenden',
  waitOffer: 'Ich kann diese Aufgabe nicht lösen',
  waitNote: 'Dein Gerät führt stattdessen eine längere Berechnung aus. Das kann einige Minuten dauern.',
  waiting: 'Berechnung läuft. Du kannst dieses Fenster offen lassen.',
  wrong: 'Das war nicht richtig. Hier ist eine neue Aufgabe.',
};

export type Strings = typeof en;

export function strings(lang: string): Strings {
  return lang.toLowerCase().startsWith('de') ? de : en;
}
