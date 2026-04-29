// Top breached/common passwords (subset of rockyou.txt + SecLists top lists).
// Used for instant local dictionary detection. HIBP k-anonymity API used for the
// full breach corpus on demand.
export const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  "123456","password","12345678","qwerty","123456789","12345","1234","111111","1234567","dragon",
  "123123","baseball","abc123","football","monkey","letmein","696969","shadow","master","666666",
  "qwertyuiop","123321","mustang","1234567890","michael","654321","superman","1qaz2wsx","7777777","121212",
  "000000","qazwsx","123qwe","killer","trustno1","jordan","jennifer","zxcvbnm","asdfgh","hunter",
  "buster","soccer","harley","batman","andrew","tigger","sunshine","iloveyou","2000","charlie",
  "robert","thomas","hockey","ranger","daniel","starwars","klaster","112233","george","computer",
  "michelle","jessica","pepper","1111","zxcvbn","555555","11111111","131313","freedom","777777",
  "pass","maggie","159753","aaaaaa","ginger","princess","joshua","cheese","amanda","summer",
  "love","ashley","nicole","chelsea","biteme","matthew","access","yankees","987654321","dallas",
  "austin","thunder","taylor","matrix","minecraft","admin","welcome","login","passw0rd","p@ssw0rd",
  "qwerty123","abcd1234","letmein123","monkey123","ninja","azerty","solo","loveme","whatever","donald",
  "batman1","trustno1!","hello","hello123","master123","starwars1","passw0rd!","admin123","root","toor",
  "changeme","secret","p@ssword","Password1","Password123","Welcome1","Welcome123","qwerty1","qwerty12",
  "iloveyou1","sunshine1","football1","dragon1","superman1","tinkle","blink182","hannah","cookie",
  "summer123","winter","spring","autumn","january","february","march","april","august","september",
]);

export function isCommonPassword(pw: string): boolean {
  if (!pw) return false;
  return COMMON_PASSWORDS.has(pw) || COMMON_PASSWORDS.has(pw.toLowerCase());
}
