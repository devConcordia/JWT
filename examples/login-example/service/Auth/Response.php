<?php

namespace Auth {
	
	/** 
	 *	
	 */
	class Response {
		
		static public function Reply( string $output, string $mimeType ) {
			
			header("Content-Type: ". $mimeType);
			
			exit( $output );
			
		}
		
		static public function ReplyJson( $output ) {
			
			if( gettype($output) != "string" )
				$output = json_encode( $output );
			
			Response::Reply( $output, "application/json" );
			
		}
		
		/** Unauthorized
		 *	
		 *	@ref https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401
		 *	
		 *	@param {string} $error
		 */
		static public function Unauthorized( string $error ) {
			
			header('WWW-Authenticate: Bearer realm="Auth"');
			header('HTTP/1.0 401 Unauthorized');
			
			Response::ReplyJson(array(
				"error" => $error
			));
			
		}
		
	}

}
