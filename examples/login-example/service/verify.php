<?php
	
	include_once("Auth/loader.php");
	
	
	$token = new Auth\JSONWebToken();
	
	
	/// caminho para os dados dos usuários
	$path = "./users/". $token->head->kid .".json";
	$user = null;
	
	/// carrega os dados do usuário, se existir
	if( file_exists($path) )
		$user = json_decode( file_get_contents( $path ) );
	
	/// caso não encontre o usuario ou falhe o carregamento do json
	if( !$user )
		Auth\Response::Unauthorized( "USER_NOT_FOUND" );
	
	
	/// verifica se o algorithmo do token é RSA
	if( substr( $token->head->alg, 0, 2 ) == "RS" ) {
		
		$key = openssl_pkey_get_public( $user->publicKey );
		
		if( !$token->verifySignature( $key ) )
			Auth\Response::Unauthorized( "ACCESS_DENIED" );
	
	} else {
		
		if( !$token->verifySignature( $user->secret ) )
			Auth\Response::Unauthorized( "ACCESS_DENIED" );
	
	}
	
	
	
	/// Uma ideia para o servidor não perder tempo validando tokens já expirados
	/// seria fazer essa verificação logo no começo
	
	/// verifica se expiry foi informado no payload
	if( isset($token->payload->expiry) ) {
		
		if( (time() - $token->payload->expiry) > 0 )
			Auth\Response::Unauthorized( "EXPIRED_TOKEN" );
		
	} else {
		
		Auth\Response::Unauthorized( "INVALID_TOKEN" );
		
	}
	
	
	
	/// o token é valido
	
	
	
	/// responde um JSON com o nome do usuário
	Auth\Response::ReplyJson((object) array(
		"status" => "OK",
		"name" => $user->name
	));
	
	
	