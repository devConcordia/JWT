
import {
	
	base64url_encode,
	base64url_decode,
	
	json_encode,
	json_decode,
	
	hmac,
	
	rsa_sign
	
} from "./common.mjs";


export default class JSONWebToken {
	
	static Create( key, header, payload ) {
		
		
		let header_json = base64url_encode( json_encode( header ) );
		let payload_json = base64url_encode( json_encode( payload ) );
		
		let content = header_json +'.'+ payload_json;
		
		let signature = "";
		
		let alg = header.alg;
		let size = Number( alg.slice(-3) );
		
		
		switch( alg.slice(0,2) ) {
			
			case 'HS':
				signature = hmac( 'sha'+ size, key, content );
				break;
		
			case 'RS':
				signature = rsa_sign( 'sha'+ size, key, content );
				break;
			
			default:
				throw 'JSW_ALG_NOT_IMPLEMENTED_OR_UNDEFINED';
				break;
			
		}
		
		return content +'.'+ base64url_encode( signature );
		
		
	}
		
}
