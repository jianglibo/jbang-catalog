
function sum(a: number, b: number) {
	return a + b;
}

function defaultParam(gpt: { a: number, b: boolean, c: string } | null = { a: 1000, b: false, c: 's' }) {
	return gpt;
}

export {
	sum, defaultParam
} 
