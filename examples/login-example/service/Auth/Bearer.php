<?php

namespace Auth {
	
	/** Bearer
	 *	
	 *	@ref https://datatracker.ietf.org/doc/html/rfc6750
	 *	
	 *	Esse método é mais seguro que o Basic Authentication, pois não 
	 *	carregam informações confidenciais diretamente.
	 *	
	 */
	class Bearer {
		
		function __construct() {
			
			$headers = apache_request_headers();
			
			/// encerra requisição se o header Authorization não informado
			if( !isset( $headers["Authorization"] ) ) 
				Response::Unauthorized("AUTH_UNDEFINED");
			
			$auth_data = explode(" ", $headers["Authorization"]);
			
			/// verifica se o scheme é do tipo `Bearer`
			/// caso não seja, encerra a requisição
			if( strtolower($auth_data[0]) != "bearer" )
				Response::Unauthorized("AUTH_TYPE_INVALID");
			
			/// deve estar codificado em base64
			$this->data = base64_decode( $auth_data[1] );
			
		}
		
	}

}
