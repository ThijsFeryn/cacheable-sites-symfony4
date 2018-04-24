<?php
/**
 * Created by PhpStorm.
 * User: thijsferyn
 * Date: 23/04/18
 * Time: 14:08
 */

namespace App\EventListener;


use Lexik\Bundle\JWTAuthenticationBundle\Event\AuthenticationFailureEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTExpiredEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTInvalidEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTNotFoundEvent;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Routing\Router;

class JwtAuthenticationListener
{
    private $httpKernel;
    private $router;
    private $requestStack;
    public function __construct(HttpKernelInterface $httpKernel, Router $router, RequestStack $requestStack)
    {
        $this->httpKernel = $httpKernel;
        $this->router = $router;
        $this->requestStack = $requestStack;
    }

    public function onJWTInvalid(JWTInvalidEvent $event)
    {
        $this->redirectToLogin($event);
    }

    public function onJWTExpired(JWTExpiredEvent $event)
    {
        $this->redirectToLogin($event);
    }

    public function onJWTNotFound(JWTNotFoundEvent $event)
    {
        $this->redirectToLogin($event);
    }

    private function redirectToLogin(AuthenticationFailureEvent $event)
    {
        $request = $this->requestStack->getMasterRequest();
        $attributes = [
            '_controller' => 'App\Controller\DefaultController:login',
            'request' => $request
        ];
        if($this->router->match($request->getPathInfo())['_route'] == 'login') {
           $event->setResponse(
               $this->httpKernel->handle(
                   $request->duplicate($request->query->all(), null, $attributes),
                   HttpKernelInterface::SUB_REQUEST
               )
           );
        } else {
           $event->setResponse(new RedirectResponse($this->router->generate('login',['error'=>$event->getException()->getMessage()])));
        }
    }
}