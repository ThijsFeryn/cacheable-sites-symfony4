<?php
namespace App\Service;
use Firebase\JWT\JWT;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Router;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class JwtAuthenticator extends AbstractGuardAuthenticator
{
    protected $key;
    protected $router;

    public function __construct($key, Router $router)
    {
        $this->key = $key;
        $this->router = $router;
    }
    private function getJwtPayload($token)
    {
        try {
            $data = JWT::decode($token,$this->key,['HS256']);
            $data = (array)$data;
            return $data;
        } catch(\UnexpectedValueException $e) {
            return false;
        }
    }
    private function jwt($username)
    {
        $data = [
            'sub'=>$username,
            'jti' => uniqid('',true),
            'exp'=>time() + (4 * 24 * 60 * 60),
            'login'=>true
        ];
        return JWT::encode($data,$this->key);
    }

    public function supports(Request $request)
    {
        $jwtPayload = $this->getJwtPayload($request->cookies->get('token'));
        if ($this->router->match($request->getPathInfo())['_route'] == 'login'
            && $request->isMethod('POST')
            && !isset($jwtPayload['sub'])){
            return true;
        }
        return false;
    }

    public function getCredentials(Request $request)
    {
            $jwtPayload = $this->getJwtPayload($request->cookies->get('token'));
            if(isset($jwtPayload['sub'])) {
                return [
                    'username' => $jwtPayload['sub'],
                    'jti' => $jwtPayload['jti']
                ];
            }
            return [
                'username' => $request->get('_username'),
                'password' => $request->get('_password')
            ];
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        if (!$userProvider instanceof InMemoryUserProvider) {
            return;
        }
        try {
            return $userProvider->loadUserByUsername($credentials['username']);
        }
        catch (UsernameNotFoundException $e) {
            throw new CustomUserMessageAuthenticationException('Invalid credentials');
        }
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        if(isset($credentials['jti']) || password_verify($credentials['password'],$user->getPassword())) {
            return true;
        }
        throw new CustomUserMessageAuthenticationException('Invalid credentials');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $response = new RedirectResponse($this->router->generate('private'));
        $response->headers->setCookie(new Cookie("token",$this->jwt($token->getUsername()), time() + (3600 * 48), '/', null, false, false));
        return $response;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new RedirectResponse($this->router->generate('login'));
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        /*$jwtPayload = $this->getJwtPayload($request->cookies->get('token'));
        if(isset($jwtPayload['sub'])) {
            return new Response('all is good in the hood');
        }*/
        return new RedirectResponse($this->router->generate('login'));
    }

    public function supportsRememberMe()
    {
        return false;
    }
}