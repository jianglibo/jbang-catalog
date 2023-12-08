import { cid } from './cfg'


declare global {
	interface Window {
		a: number;
	}
}

let uniqueIdSet = new Set();
window.a = 1;

/// <reference lib="dom" />

console.log(cid)

export function foo() {
	return 'foo';
}