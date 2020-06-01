<?php namespace App\Libraries;

use \UnexpectedValueException;
use CodeIgniter\I18n\Time;

/**
 * Class EasyJWT
 *
 * @package  App\Libraries
 * @category Authentication
 * @author   Rui Valim Junior <r.valim.junior@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link	 https://github.com/Ruivalim/ci4-easyjwt
 */

class EasyJWT
{
	protected $private_key = "";
	protected $public_key  = null;
	protected $alg         = "HS256";
	protected $iss         = "";
	protected $algorithms  = array(
		'HS256' => array('hash_hmac', 'SHA256'),
		'HS384' => array('hash_hmac', 'SHA384'),
		'HS512' => array('hash_hmac', 'SHA512'),
		'RS256' => array('openssl', 'SHA256'),
		'RS384' => array('openssl', 'SHA384'),
		'RS512' => array('openssl', 'SHA512')
	);

	/**
	 *  Class Constructor
	 * 
	 *  Set the variables according the configuration file
	 */
	public function __construct()
	{
		$jwt_config = new \Config\EasyJWT;

		$this->iss = $jwt_config->iss;
		$this->alg = $jwt_config->alg;

		if( $this->algorithms[$this->alg][0] == "openssl" ){
			if(\file_exists(ROOTPATH.$jwt_config->public_key)){
				$this->public_key  = \openssl_pkey_get_public("file://".ROOTPATH.$jwt_config->public_key);
			}else{
				$this->public_key  = \openssl_pkey_get_public($jwt_config->public_key);
			}
			if(\file_exists(ROOTPATH.$jwt_config->private_key)){
				$this->private_key = \openssl_pkey_get_private("file://".ROOTPATH.$jwt_config->private_key, $jwt_config->private_key_password);
			}else{
				$this->private_key = \openssl_pkey_get_private($jwt_config->private_key, $jwt_config->private_key_password);
			}
		}else{
			$this->public_key  = $jwt_config->public_key;
			$this->private_key = $jwt_config->private_key;
		}

		if( $this->iss === "" ){
			$this->iss = base_url();
		}
	}

	/**
	 * Generate JWT
	 * 
	 * @param array  $payload	  The payload for the token
	 * @param string $expiration   Token lifetime
	 * @param array  $extraHeader  Extra header data
	 * 
	 * @return string The JWT
	 */
	public function generate($payload, $expiration = "+5 minutes", $extraHeader = null)
	{
		$header = array(
			'typ' => 'JWT', 
			'alg' => $this->alg
		);
		
		if (isset($extraHeader) && \is_array($extraHeader)) {
			$header = \array_merge($header, $extraHeader);
		}

		$now = new Time('now');
		$exp = new Time($expiration);
		
		$defaultPayload = array(
			'iss' => $this->iss,
			'iat' => $now->getTimestamp(),
			'exp' => $exp->getTimestamp()
		);

		$payload = \array_merge($defaultPayload, $payload);

		$token = array();
		$token[] = $this->urlSafe_B64Encode($this->json_clean_encode($header));
		$token[] = $this->urlSafe_B64Encode($this->json_clean_encode($payload));
		$signing_input = \implode('.', $token);

		$signature = $this->sign($signing_input);
		$token[] = $this->urlSafe_B64Encode($signature);

		return \implode('.', $token);
	}

	/**
	 * Decode JWT
	 * 
	 * @param string  $token			 Token to decode
	 * @param boolean $returnArray	   Choose to return either array or object
	 * @param array   $extraVerification Extra verificaiton to do in the token
	 * 
	 * @throws UnexpectedValueException Throws invalid token
	 * @throws UnexpectedValueException Throws invalid signature
	 * @throws UnexpectedValueException Throws expired token
	 * @throws UnexpectedValueException Throws invalid issuer
	 * @throws UnexpectedValueException Throws invalid issued time
	 * @throws UnexpectedValueException Throws extra verification error
	 * 
	 * @return array|object Return the payload from the token
	 */
	public function decodeToken($token, $returnArray = false, $extraVerification = null)
	{
		$token = explode(".", $token);

		if( \count($token) != 3 ){
			throw new UnexpectedValueException('Invalid Token');
		}

		$header	= $this->json_clean_decode($this->urlSafe_B64Decode($token[0]), $returnArray);
		$payload   = $this->json_clean_decode($this->urlSafe_B64Decode($token[1]), $returnArray);
		$signature = $this->urlSafe_B64Decode($token[2]);
		
		if( $returnArray ){	
			$exp = $payload['exp'];
			$iat = $payload['iat'];
			$iss = $payload['iss'];
			$alg = $header['alg'];
		}else{
			$exp = $payload->exp;
			$iat = $payload->iat;
			$iss = $payload->iss;
			$alg = $header->alg;
		}

		if( !$this->verify_token($token[0].".".$token[1], $signature, $alg) ){
			throw new UnexpectedValueException('Invalid Signature');
		}

		$now = new Time('now');
		$now = $now->getTimestamp();

		if( $exp <= $now ){
			throw new UnexpectedValueException('Expired token');
		}

		if( $iat > $now ){
			throw new UnexpectedValueException('Invalid issued time');
		}

		if( $iss !== $this->iss ){
			throw new UnexpectedValueException('Invalid issuer');
		}

		if( $extraVerification !== null && \is_array($extraVerification) ){
			foreach( $extraVerification as $section => $data ){
				$section_to_check = null;

				if( $section == "header" ){
					$section_to_check = $header;
				}else if( $section == "payload" ){
					$section_to_check = $payload;
				}

				if( $data !== null ){
					foreach( $data as $param => $verification ){
						switch($verification['method']){
							case "equal":
								$value;
								if( $returnArray ){
									$value = $section_to_check[$param];
								}else{
									$value = $section_to_check->$param;
								}

								if( $value !== $verification['value'] ){
									throw new UnexpectedValueException($verification['on_error_message']);
								}

								break;
							case "more":
								$value;
								if( $returnArray ){
									$value = $section_to_check[$param];
								}else{
									$value = $section_to_check->$param;
								}

								if( intval($value, 10) >= intval($verification['value'], 10) ){
									throw new UnexpectedValueException($verification['on_error_message']);
								}

								break;
							case "less":
								$value;
								if( $returnArray ){
									$value = $section_to_check[$param];
								}else{
									$value = $section_to_check->$param;
								}

								if( intval($value, 10) <= intval($verification['value'], 10) ){
									throw new UnexpectedValueException($verification['on_error_message']);
								}

								break;
							case "equal-more":
								$value;
								if( $returnArray ){
									$value = $section_to_check[$param];
								}else{
									$value = $section_to_check->$param;
								}

								if( intval($value, 10) > intval($verification['value'], 10) ){
									throw new UnexpectedValueException($verification['on_error_message']);
								}

								break;
							case "equal-less":
								$value;
								if( $returnArray ){
									$value = $section_to_check[$param];
								}else{
									$value = $section_to_check->$param;
								}

								if( intval($value, 10) < intval($verification['value'], 10) ){
									throw new UnexpectedValueException($verification['on_error_message']);
								}

								break;
						}
					}
				}
			}
		}
		
		return $payload;
	}

	/**
	 * Create token signature
	 * 
	 * @param string  $data Data to create signature
	 * 
	 * @throws UnexpectedValueException Throws OpenSSL signature error
	 * 
	 * @return string The token signature
	 */
	public function sign($data)
	{
		$alg = $this->alg;
		$key = $this->private_key;

		list($function, $algorithm) = $this->algorithms[$alg];
		
		if( $function == "openssl" ){
			$signature = '';
			$success = \openssl_sign($data, $signature, $key, $algorithm);
			if (!$success) {
				throw new UnexpectedValueException("OpenSSL unable to sign data");
			} else {
				return $signature;
			}
		}else{
			return \hash_hmac($algorithm, $data, $key, true);
		}
	}

	/**
	 * Verify Signature
	 * 
	 * @param string $data	  Data to verify
	 * @param string $signature Signature to validate
	 * @param string $alg	   Algorithm to validate
	 * 
	 * @throws UnexpectedValueException Throws OpenSSL verification error
	 * 
	 * @return boolean
	 */
	public function verify_token($data, $signature, $alg)
	{
		$key = $this->private_key;

		if( $this->algorithms[$this->alg][0] == "openssl" ){
			$key = $this->public_key;
		}

		list($function, $algorithm) = $this->algorithms[$alg];
		
		if( $function == "openssl" ){
			$success = \openssl_verify($data, $signature, $key, $algorithm);
			if ($success === 1) {
				return true;
			} elseif ($success === 0) {
				return false;
			}

			throw new UnexpectedValueException('OpenSSL error: ' . \openssl_error_string() );
		}else{
			$hash = \hash_hmac($algorithm, $data, $key, true);
			if (\function_exists('hash_equals')) {
				return \hash_equals($signature, $hash);
			}
			$len = \min(\strlen($signature), \strlen($hash));

			$status = 0;
			for ($i = 0; $i < $len; $i++) {
				$status |= (\ord($signature[$i]) ^ \ord($hash[$i]));
			}
			$status |= (\strlen($signature) ^ \strlen($hash));

			return ($status === 0);
		}
	}

	/**
	 * Encode a string with URL-safe Base64.
	 *
	 * @param string  $data The string that will be encoded
	 *
	 * @return string The base64 string encode
	 */
	public function urlSafe_B64Encode($data)
	{
		if( \is_array($data) ){
			$data = $this->json_clean_encode($data);
		}

		return \rtrim(\strtr(\base64_encode($data), '+/', '-_'), "=");
	}

	/**
	 * Decode a string with URL-safe Base64.
	 *
	 * @param string  $data A Base64 encoded string
	 *
	 * @return string A decoded string
	 */
	public function urlSafe_B64Decode($data)
	{
		$padLen = 4 - (\strlen($data) % 4);
		$data .= \str_repeat('=', $padLen);
		
		return \base64_decode(\strtr($data, '-_', '+/'));
	}
	
	/**
	 * Encode an array into JSON
	 * 
	 * @param array   $data The array that will be encoded
	 * 
	 * @throws UnexpectedValueException Throws JSON encode error 
	 * 
	 * @return string The JSON string encoded
	 */
	public function json_clean_encode($data)
	{
		$json = \json_encode($data, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);

		if (\json_last_error() !== JSON_ERROR_NONE) {
			$error = \json_last_error();

			$errorMessages = array(
				JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
				JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
				JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
				JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
				JSON_ERROR_UTF8 => 'Malformed UTF-8 characters'
			);

			throw new UnexpectedValueException( isset($errorMessages[$error]) ? $errorMessages[$error] : 'Unknown JSON error: ' . $error );
		}

		return $json;
	}

	/**
	 * Decode JSON string into object
	 * 
	 * @param string  $data		The JSON string that will be decoded
	 * @param boolean $returnArray Choose to return either array or object
	 * 
	 * @throws UnexpectedValueException Throws JSON decode error
	 * 
	 * @return object|array The object or array from the JSON string inputed
	 */
	public function json_clean_decode($data, $returnArray = false)
	{
		$data = \preg_replace("#(/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|([\s\t]//.*)|(^//.*)#", '', $data);
		
		if(\version_compare(\phpversion(), '5.4.0', '>=')) {
			$data = \json_decode($data, $returnArray, 512, JSON_BIGINT_AS_STRING);
		}elseif(\version_compare(\phpversion(), '5.3.0', '>=')) {
			$data = \json_decode($data, $returnArray, 512);
		}else {
			$data = \json_decode($data, $returnArray);
		}

		if (\json_last_error() !== JSON_ERROR_NONE) {
			$error = \json_last_error();

			$errorMessages = array(
				JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
				JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
				JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
				JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
				JSON_ERROR_UTF8 => 'Malformed UTF-8 characters'
			);

			throw new UnexpectedValueException( isset($errorMessages[$error]) ? $errorMessages[$error] : 'Unknown JSON error: ' . $error );
		}
	
		return $data;
	}
}

/**
 * -----------------------------------------------------------------------
 * Filename: EasyJWT.php
 * Location: ./app/Libraries/EasyJWT.php
 * -----------------------------------------------------------------------
 */ 