const crypto = require('crypto');
const bcrypt = require('bcrypt');

module.exports = {
	md5(str) {
		const hash = crypto.createHash('md5');
		hash.update(str);
		return hash.digest('hex');
	},
	isMD5(hash) {
		return (/[a-fA-F0-9]{32}/).test(hash);
	},
	bcrypt(str) {
		return bcrypt.hashSync(str, 12);
	},
	compareBcrypt: bcrypt.compareSync,
}