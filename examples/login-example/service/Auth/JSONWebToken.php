<?php

namespace Auth {

	/** JSONWebToken
	 *	
	 *	@ref https://jwt.io/
	 *	@ref https://datatracker.ietf.org/doc/html/rfc6750
	 *	
	 *	Este método é mais comumente associado ao protocolo OAuth 2.0,
	 *	do qual são utilizados os JSONWebToken e JSONWebSignature
	 *	O cliente recebe um token de acesso (Bearer token) após a
	 * 	autenticação bem-sucedida com um servidor de autorização.
	 *	
	 *	O token é então enviado no cabeçalho Authorization como Bearer <token>
	 *		
	 *		Authorization: Bearer HEAD . PAYLOAD . SIGNATURE
	 *		Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
	 *	
	 *	Observação:
	 *	Em alguns casos, o serviço pode exigir que JWT seja codificado em base64 (além de cada uma das partes).
	 *	Como é o caso desse projeto, esse tratamento é realizado na class Bearer.
	 *	
	 *		Authorization: Bearer ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeE1qTTBOVFkzT0Rrd0lpd2libUZ0WlNJNklrcHZhRzRnUkc5bElpd2lhV0YwSWpveE5URTJNak01TURJeWZRLlNmbEt4d1JKU01lS0tGMlFUNGZ3cE1lSmYzNlBPazZ5SlZfYWRRc3N3NWM
	 *	
	 *	Esse método é mais seguro que o Basic Authentication, pois os tokens podem 
	 *	ter vida útil limitada e não carregam informações confidenciais diretamente.
	 *	
	 *	
	 */
	class JSONWebToken extends Bearer {
		
		function __construct() {
			
			parent::__construct();
			
			$token = explode( ".", $this->data );
			
			$this->token = $token;
			
			$this->head = json_decode( base64url_decode($token[0]) );
			$this->payload = json_decode( base64url_decode($token[1]) );
			$this->signature = $token[2];
			
		}
		
		/** verifySignature
		 *	
		 *	@param {*} $key				O valor poderá ser diferente dependendo do algoritmo de assinatura utilizado
		 *								caso seja HS***, deverá ser uma string; caso seja RS***, deverá ser uma instancia
		 *								de chave publica rsa já inciada com "openssl_pkey_get_public"
		 */
		public function verifySignature( $key ) {
			
			$signature = base64url_decode( $this->signature );
			
			$content = $this->token[0] .".". $this->token[1];
			
			/// 
			$alg = $this->head->alg;
			
			switch( $alg ) {
				
				case "HS256":
				case "HS384":
				case "HS512":
					$type = "sha". substr( $alg, 2 );
					return hash_hmac( $type, $content, $key, true ) === $signature;
					break;
				
				case "RS256":
					return openssl_verify( $content, $signature, $key, OPENSSL_ALGO_SHA256 );
					break;
					
				case "RS384":
					return openssl_verify( $content, $signature, $key, OPENSSL_ALGO_SHA384 );
					break;
					
				case "RS512":
					return openssl_verify( $content, $signature, $key, OPENSSL_ALGO_SHA512 );
					break;
				
				default:
						throw new Exception("JSW_ALG_NOT_IMPLEMENTED_OR_UNDEFINED",1);
					break;
				
			}
			
			return false;
			
		}
		
		
		/** Create
		 *	
		 *	@param {*} $key				O valor poderá ser diferente dependendo do algoritmo de assinatura utilizado
		 *								caso seja HS***, deverá ser uma string; caso seja RS***, deverá ser uma instancia
		 *								de chave privada rsa já inciada com "openssl_pkey_get_private"
		 *	@param {object} $head
		 *	@param {object} $payload
		 *	@return {string}
		 */
		static public function Create( $key, object $head, object $payload ) {
			
			$head_json = json_encode( $head );
			$payload_json =  json_encode( $payload );
			
			///
			$content = base64url_encode( $head_json ) .".". base64url_encode( $payload_json );
			
			$signature = "";
			
			///
			switch( $head->alg ) {
				
				case "HS256":
				case "HS384":
				case "HS512":
					$type = "sha". substr( $head->alg, 2 );
					$signature = hash_hmac( $type, $content, $key, true );
					break;
				
				case "RS256":
					
					if( !openssl_sign( $content, $signature, $key, OPENSSL_ALGO_SHA256 ) )
						throw new Exception("RSA_SIGN_SHA256_FAILURE",1);
					
					break;
					
				case "RS384":
					
					if( !openssl_sign( $content, $signature, $key, OPENSSL_ALGO_SHA384 ) )
						throw new Exception("RSA_SIGN_SHA384_FAILURE",1);
					
					break;
					
				case "RS512":
					
					if( !openssl_sign( $content, $signature, $key, OPENSSL_ALGO_SHA512 ) )
						throw new Exception("RSA_SIGN_SHA512_FAILURE",1);
					
					break;
				
				default:
						throw new Exception("JSW_ALG_NOT_IMPLEMENTED_OR_UNDEFINED",1);
					break;
				
			}
			
			///
			return $content .".". base64url_encode( $signature );
			
		}
		
		
		
	}

}
