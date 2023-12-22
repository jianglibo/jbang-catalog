import { defaultParam, sum } from './sum';

test('adds 1 + 2 to equal 3', () => {
	expect(sum(1, 2)).toBe(3);
});

test('defaultParam', () => {
	expect(defaultParam({ a: 1000, b: false, c: 's' })).toEqual({ a: 1000, b: false, c: 's' });
	expect(defaultParam({ a: 1001, b: true, c: 's1' })).toEqual({ a: 1001, b: true, c: 's1' });
	expect(defaultParam(null)).toEqual(null);
})