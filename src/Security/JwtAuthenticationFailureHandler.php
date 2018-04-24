<?php
namespace App\Security;

use Lexik\Bundle\JWTAuthenticationBundle\Security\Http\Authentication\AuthenticationFailureHandler as LexikAuthenticationFailureHandler;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Router;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\HttpFoundation\RedirectResponse;

class JwtAuthenticationFailureHandler extends LexikAuthenticationFailureHandler
{
    private $router;
    public function __construct(EventDispatcherInterface $dispatcher, Router $router)
    {
        parent::__construct($dispatcher);
        $this->router = $router;
    }
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new RedirectResponse($this->router->generate('login',['error'=>$exception->getMessage()]));
    }
}