<?php
namespace App\Security;

use Lexik\Bundle\JWTAuthenticationBundle\Security\Http\Authentication\AuthenticationSuccessHandler as LexikAuthenticationSuccessHandler;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTManager;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\Routing\Router;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
class JwtAuthenticationSuccessHandler extends LexikAuthenticationSuccessHandler
{
    private $router;
    private $jwtTtl;
    public function __construct(JWTManager $jwtManager, EventDispatcherInterface $dispatcher, Router $router, $jwtTtl=0)
    {
        parent::__construct($jwtManager,$dispatcher);
        $this->router = $router;
        $this->jwtTtl = (int)$jwtTtl;
    }
    public function handleAuthenticationSuccess(UserInterface $user, $jwt = null)
    {
        if (null === $jwt) {
            $jwt = $this->jwtManager->create($user);
        }

        $expire = 0;
        if($this->jwtTtl != 0) {
            $expire = time() + $this->jwtTtl;
        }

        $response = new RedirectResponse($this->router->generate('private'));
        $response->headers->setCookie(new Cookie('token',$jwt, $expire, '/', null, false, false));
        return $response;
    }
}