// Public diagnostics identify a fixed boundary, never the underlying exception.
// Native stderr and WASM errors may include input, file paths or component
// secrets; neither an arbitrary string nor Error.message may enter a report.
const LABELS=Object.freeze({
 'signing-preparation':'Preparing the browser signature',
 'native-signature':'Obtaining the native signature components',
 'companion-completion':'Restoring the companion and completing its signature component',
 'signature-finalization':'Verifying and assembling the final OpenPGP signature',
 'recipient-encryption':'Encrypting the signed message for the recipient',
 'signing-protocol':'Checking the signing operation binding and response',
 'signing-worker':'Running the disposable browser signing worker',
 'signing-timeout':'Waiting for the signing operation to complete',
 'signing-cancelled':'Cancelling the signing operation',
 'signing-unknown':'Signing boundary unavailable'
});

// Treat codes from workers, injected providers and saved reports as untrusted.
// An unknown value is replaced, not interpolated into a supposedly safe label.
export function signingFailurePhase(value){return typeof value==='string'&&Object.hasOwn(LABELS,value)?value:'signing-unknown';}
export function signingFailureLabel(value){return LABELS[signingFailurePhase(value)];}
export function signingFailure(message,phase){const error=Error(message);error.failurePhase=signingFailurePhase(phase);return error;}
