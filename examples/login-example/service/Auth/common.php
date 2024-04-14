<?php

namespace Auth {

	/** base64url_encode
	 *	
	 *	@ref https://www.php.net/manual/en/function.base64-encode.php
	 *	
	 *	@param {string} $data
	 *	@return {string}
	 */
	function base64url_encode( string $data ) {
		
	//	return base64_encode($data);
		
		return rtrim( strtr( base64_encode($data), '+/', '-_'), '=');

	}


	/** base64url_decode
	 *	
	 *	@ref https://www.php.net/manual/en/function.base64-encode.php
	 *	@ref https://www.php.net/manual/en/function.base64-decode.php
	 *	
	 *	@param {string} $data
	 *	@return {string}
	 */
	function base64url_decode( string $data ) {

	//	return base64_decode($data);
		
		return base64_decode( str_pad( strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT) );

	}

}
