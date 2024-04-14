
# JWT

Este projeto é um estudo de autenticação utilizando [JWT](https://jwt.io/) (JSON Web Token) em PHP e Javascript.

> Os testes foram realizados utilizando o XAMPP


## Login Example

A ideia desse exemplo é o JWT ser gerado do lado do cliente (utilizando o [forge](https://github.com/digitalbazaar/forge)) e então verificado no servidor.

Os algortimos testados foram HMAC (para uso de chave simétrica) e RSA (para uso de chaves assimétricas).


Algumas observações:
- No `head` do JWT, utilizamos na propriedade `kid` (KeyID) para identificar as chaves do usuário.
- No `payload`, definimos a propriedade `expiry`, que é o instante que token deixará de ser valido. O valor deverá ser um *timestamp* em segundos.


### HMAC

No caso do uso de chave simetrica, o usuário informa seu id e seu segredo.

```javascript

let head = new Object();
    head.alg = "HS256";
    head.kid = userId;

let payload = new Object();
    payload.expiry = Math.floor(Date.now()/1000) + 300;

let token = JSONWebToken.Create( secret, head, payload );

```

### RSA

No caso do uso de chave assimétricas, será preciso informar a cahve privada do usuário.
No exemplo utilizamos um [HTMLInputELement](https://developer.mozilla.org/pt-BR/docs/Web/API/HTMLInputElement) com o `type` definido com *file* 
e o [FileReader](https://developer.mozilla.org/pt-BR/docs/Web/API/FileReader) para obter a chave privada.
Além da chave correta `privateKey.pem`, subi uma chave falsa (`privateKey-fake.pem`) para testar se a validação está correta.

```javascript

let fileReader = new FileReader();
    fileReader.onload = function() {

        let head = new Object();
            head.alg = "RS256";
            head.kid = userId;

        let payload = new Object();
            payload.expiry = Math.floor(Date.now()/1000) + 300;

        let privateKey = forge.pki.privateKeyFromPem( fileReader.result );

        let token = JSONWebToken.Create( privateKey, head, payload );

    };
	
    fileReader.readAsText( inPrivateKey.files[0] );
	
```


## Verificação

A verificação é um processo de multiplas etapas, e se alguma delas falhar,
a requsição será encerrada com o erro 401.

Ao iniciar a classe, o token será lido do `header` da requisição HTTP.

```php
$token = new Auth\JSONWebToken();
```

Para verificar a assinatura do token, precisamos obter as chaves do usuário.
Nesse exemplo, estamos salvando os dados do usuário como json no diretório *users*.

```php

$path = "./users/". $token->head->kid .".json";
$user = null;

if( file_exists($path) )
    $user = json_decode( file_get_contents( $path ) );

/// caso não encontre o usuario ou falhe a verificação
if( !$user )
    Auth\Response::Unauthorized( "USER_NOT_FOUND" );
	
```

Antes de verificar se o token é valido, precisamos identificar o algoritimo utilizado.
Se for RSA, a chave precisa ser inciada com `openssl_pkey_get_public`.

```php

/// verifica se o algorithmo do token é RSA
if( substr( $token->head->alg, 0, 2 ) == "RS" ) {
	
    $key = openssl_pkey_get_public( $user->publicKey );
	
    if( !$token->verifySignature( $key ) )
        Auth\Response::Unauthorized( "ACCESS_DENIED" );

} else {
	
    if( !$token->verifySignature( $user->secret ) )
        Auth\Response::Unauthorized( "ACCESS_DENIED" );

}

```

E por ultimo, verifica se o token possui a informação da validade ou se já expirou.

```php

/// verifica se expiry foi informado no payload
if( isset($token->payload->expiry) ) {
		
    if( (time() - $token->payload->expiry) > 0 )
        Auth\Response::Unauthorized( "EXPIRED_TOKEN" );
	
} else {
	
    Auth\Response::Unauthorized( "INVALID_TOKEN" );
	
}

```


