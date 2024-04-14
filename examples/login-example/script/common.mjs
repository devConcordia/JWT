

/** base64_encode
 *	
 *	@param {String} input
 *	@return {String}
 */
const base64_encode = btoa;

/** base64_decode
 *	
 *	@param {String} input
 *	@return {String}
 */
const base64_decode = atob;



/** base64url_encode
 *	
 *	@ref https://www.php.net/manual/en/function.base64-encode.php
 *	
 *	@param {string} $data
 *	@return {string}
 */
function base64url_encode( data ) {

	data = base64_encode(data);
	data = data.replace(/\+/gm, '-');
	data = data.replace(/\//gm, '_');
	
	return data.replace(/\=/gm, '');

}


/** base64url_decode
 *	
 *	@ref https://www.php.net/manual/en/function.base64-encode.php
 *	@ref https://www.php.net/manual/en/function.base64-decode.php
 *	
 *	@param {string} $data
 *	@return {string}
 */
function base64url_decode( data ) {

	data = data.replace(/\-/gm, '+');
	data = data.replace(/\_/gm, '/');
	
	data = data.padEnd( data.length%4, '=' );
	
	return base64_decode(data)
	
}


/** json_encode
 *	
 *	@param {Object} input
 *	@return {String}
 */
const json_encode = JSON.stringify;

/** json_decode
 *	
 *	@param {String} input
 *	@return {Object}
 */
const json_decode = JSON.parse;

/* */

/** hash
 *	
 *	@param {String} type		md5 | sha1 | sha256 | sha384 | sha512
 *	@param {String} data
 *	@return {String}
 */
function hash( type, data, encode = true ) {
	
	let md = forge.md[ type ];
	
	if( !md )
		throw 'hash type "'+ type +'" not implemented';
	
	let bytes = md.create().update( data ).digest().getBytes();
	
	if( encode )
		return base64_encode( bytes );
	
	return bytes;
	
}

/** hmac
 *	
 *	@ref https://tools.ietf.org/html/rfc2104
 *	@ref https://pt.wikipedia.org/wiki/HMAC
 *	
 *	@param {String} type		md5 | sha1 | sha256 | sha384 | sha512
 *	@param {String} secret
 *	@param {String} data
 *	@return {String}
 */
function hmac( type, secret, data ) {
	
	let hm = forge.hmac.create();
		hm.start( type, secret );
		hm.update( data );
		
	return hm.digest().getBytes();
	
}

/* */

function rsa_sign( mode, key, content ) {
	
	let md = forge.md[ mode ].create();
		md.update( content );

	return key.sign( md );
	
}

/* */

export {
	
	base64_encode,
	base64_decode,
	
	base64url_encode,
	base64url_decode,
	
	json_encode,
	json_decode,
	
	hmac,
	rsa_sign
	
}