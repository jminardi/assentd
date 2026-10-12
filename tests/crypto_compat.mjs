// Runs the real phone-side crypto (web/vcrypto.mjs) under Node and prints a vault fragment for
// the Go side (cmd/assentd/compat_test.go) to open, after opening what the Go side sealed.
import * as vc from "../web/vcrypto.mjs";

const input = JSON.parse(process.argv[2]);
const prf = vc.unb64u(input.prf);
const vmk = vc.newVmkBytes();
const recovery = vc.newRecoveryCode();
const vmkWrap = await vc.wrapVmk(await vc.kekFromPrf(prf), vmk);
const recoveryWrap = await vc.wrapVmk(await vc.kekFromRecovery(recovery.bytes), vmk);
const metaJson = vc.canonicalJson({ name: "X", modes: ["command"], max_ttl: 900, hosts: [], description: "é \"q\" ✓ <&>", created: 1 });
const key = await vc.unwrapVmk(await vc.kekFromPrf(prf), vmkWrap);
const box = await vc.sealSecret(key, metaJson, input.value);
// Open a box the Go side sealed.
const goKey = await vc.unwrapVmk(await vc.kekFromPrf(prf), input.go_vmk_wrap);
const goOpened = await vc.openSecret(goKey, input.go_meta_json, input.go_box);
// Inbox: open a deposit the daemon sealed, and make an inbox the daemon must be able to use.
const goDeposit = await vc.openDeposit(goKey, input.go_inbox_priv_box, input.go_deposit_box, input.deposit_id);
const jsInbox = await vc.newInbox(goKey);
// Recovery key: made under the Go VMK, then used to sign a reenrollment the daemon must verify.
const goVmkRaw = vc.unb64u(input.go_vmk_raw);
const recoveryKey = await vc.newRecoveryKey(goVmkRaw);
const reenrollMsg = await vc.reenrollMessage(vc.unb64u(input.challenge), vc.unb64u(input.cred_id), input.go_vmk_wrap);
const reenrollSig = await vc.signReenroll(goVmkRaw, recoveryKey.priv_box, reenrollMsg);
console.log(JSON.stringify({ recoveryKey, reenrollMsg: vc.b64u(reenrollMsg), reenrollSig, vmkWrap, recoveryWrap, recoveryText: recovery.text, metaJson, box, goOpened, goDeposit, jsInbox }));
