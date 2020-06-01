<?php namespace Config;

/**
 * EasyJWT configuration.
 *
 */

use CodeIgniter\Config\BaseConfig;

Class EasyJWT extends BaseConfig 
{
	/**
	 *  Private Key
	 * 
	 *  Private Key used to validate token
	 */

	public $private_key = "";

	/**
	 *  Private Key Password
	 * 
	 *  Private Key Password used to validate token
	 */

	public $private_key_password = "";

	/**
	 *  Public Key
	 * 
	 *  Public Key used to validate token
	 */

	public $public_key = null;

	/**
	 *  Algorithm
	 * 
	 *  Algorithm used encrypt the signature
	 */
	public $alg = "HS256";

	/**
	 *  Issuer
	 * 
	 *  Set iss value of payload
	 */
	public $iss = "";
}