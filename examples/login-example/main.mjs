
//import { base64_encode, base64_decode, base64url_encode, base64url_decode } from './script/common.mjs';
import JSONWebToken from './script/JSONWebToken.mjs';

function http_request( url, data, header, callback ) {
	
	var xhr = new XMLHttpRequest();
		xhr.onreadystatechange = function() {
		
			if( xhr.readyState === XMLHttpRequest.DONE ) {
				switch( xhr.status ) {
					
					case 200:
					case 401:
						callback( xhr.response );
						break;
					
					default:
						callback(null);
						break;
				}
			}
			
		};

	xhr.open( 'POST', url, true );
	
	for( var key in header )
		xhr.setRequestHeader( key, header[key] );
	
	xhr.send( data );

}

/** 
 *	
 */
window.addEventListener('load', function() {
	
	
	function verifyUser( token, callback ) {
		
		let url = 'service/verify.php';
		let data = null;
		
		let header = new Object;
			header["Authorization"] = "Bearer "+ btoa( token );
		
		
		http_request( url, data, header, function(response) {
			
			try {
			
				response = JSON.parse(response);
			
			} catch(err) {}
			
			if( callback instanceof Function )
				callback( response );
			
		});

	}
	
	
	let inUserId = document.body.querySelector('#in-userid');
	let inSecret = document.body.querySelector('#in-secret');
	let inPrivateKey = document.body.querySelector('#in-privatekey');
	
	let btnAccessHS256 = document.body.querySelector('#btn-access-hs256');
	
		btnAccessHS256.addEventListener('click', function() {
			
			
			let head = new Object();
				head.alg = "HS256";
				head.kid = inUserId.value;

			let payload = new Object();
				payload.expiry = Math.floor(Date.now()/1000) + 300;

			
			///
			let token = JSONWebToken.Create( inSecret.value, head, payload );
			
			verifyUser( token, function(res) {
				
				console.log( res );
			
				if( res.status == 'OK' ) {
				
					alert( "Welcome "+ res.name +"!" );
				
				} else {
					
					alert( res.error || "Ops ... Ocorreu algum erro no servidor." );
					
				}
				
			});
			
		}, false);
	
	let btnAccessRS256 = document.body.querySelector('#btn-access-rs256');
	
		btnAccessRS256.addEventListener('click', function() {
			
			if( inPrivateKey.files.length == 0 )
				return alert("Carrege o arquvio privateKey.pem");
			
			let fileReader = new FileReader();
				fileReader.onload = function() {
					
					
					let head = new Object();
						head.alg = "RS256";
						head.kid = inUserId.value;

					let payload = new Object();
						payload.expiry = Math.floor(Date.now()/1000) + 300;

					
					let privateKey = forge.pki.privateKeyFromPem( fileReader.result );
					
					///
					let token = JSONWebToken.Create( privateKey, head, payload );
					
					console.log( token );
					
					verifyUser( token, function(res) {
						
						if( res.status == 'OK' ) {
						
							alert( "Welcome "+ res.name +"!" );
						
						} else {
							
							alert( res.error || "Ops ... Ocorreu algum erro no servidor." );
							
						}
						
					});

					
				};
			
				
				fileReader.readAsText( inPrivateKey.files[0] );
			
			
			
		}, false);
	
	
	
	
	
}, false);

