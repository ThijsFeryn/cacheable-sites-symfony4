<?php
namespace App\Service;
use Firebase\JWT\JWT;
use Symfony\Component\HttpFoundation\Cookie;
class JwtAuthentication
{
    protected $key;
    protected $username;
    protected $password;

    public function __construct($key,$username,$password)
    {
        $this->key = $key;
        $this->username = $username;
        $this->password = $password;
    }


    public function jwt($username)
    {
        return JWT::encode([
            'sub'=>$username,
            'exp'=>time() + (4 * 24 * 60 * 60),
            //'exp'=>time() + 60,
            'login'=>true,
        ],$this->key);
    }

    public function createCookie($username)
    {
        return new Cookie("token",$this->jwt($username), time() + (3600 * 48), '/', null, false, false);
    }

    public function validate($token)
    {
        try {
            $data = JWT::decode($token,$this->key,['HS256']);
            $data = (array)$data;
            if($data['sub'] !== $this->username) {
                return false;
            }
            return true;
        } catch(\UnexpectedValueException $e) {
            return false;
        }
    }
}