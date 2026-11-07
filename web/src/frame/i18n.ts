const en = {
  verifying: 'Verifying you are human',
  working: 'Checking your browser',
  verified: 'Verified',
  failed: 'Verification failed',
  retry: 'Try again',
  denied: 'We could not verify this browser.',
  contact: 'Contact support',
  brand: 'SweetCaptcha',
  puzzleTitle: 'One more step',
  lineTrace: 'Follow each marked line from the left to its number on the right.',
  lineCircle: 'The line from the circle ends at:',
  lineSquare: 'The line from the square ends at:',
  gapRings: 'Select every ring that has a gap.',
  cell: 'Cell',
  rotate: 'Turn each right-hand shape until it matches the shape to its left.',
  rotateLabel: 'Rotation of shape',
  submit: 'Submit',
  waitOffer: 'Skip the puzzle and wait instead',
  waitNote: 'Your device does a longer calculation. No task is needed. This can take a minute.',
  waiting: 'Calculating. You can leave this open.',
  wrong: 'That was not right. Here is a new one.',
};

const de: typeof en = {
  verifying: 'Überprüfung läuft',
  working: 'Browser wird geprüft',
  verified: 'Verifiziert',
  failed: 'Überprüfung fehlgeschlagen',
  retry: 'Erneut versuchen',
  denied: 'Dieser Browser konnte nicht verifiziert werden.',
  contact: 'Support kontaktieren',
  brand: 'SweetCaptcha',
  puzzleTitle: 'Noch ein Schritt',
  lineTrace: 'Folge jeder markierten Linie von links bis zu ihrer Zahl rechts.',
  lineCircle: 'Die Linie vom Kreis endet bei:',
  lineSquare: 'Die Linie vom Quadrat endet bei:',
  gapRings: 'Wähle jeden Ring aus, der eine Lücke hat.',
  cell: 'Feld',
  rotate: 'Drehe jede rechte Form, bis sie zur linken Form passt.',
  rotateLabel: 'Drehung der Form',
  submit: 'Absenden',
  waitOffer: 'Rätsel überspringen und stattdessen warten',
  waitNote: 'Dein Gerät führt eine längere Berechnung aus. Es ist keine Aufgabe nötig. Das kann eine Minute dauern.',
  waiting: 'Berechnung läuft. Du kannst dieses Fenster offen lassen.',
  wrong: 'Das war nicht richtig. Hier ist eine neue Aufgabe.',
};

export type Strings = typeof en;

export function strings(lang: string): Strings {
  return lang.toLowerCase().startsWith('de') ? de : en;
}
