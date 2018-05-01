<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\RedirectResponse;
use App\Service\JwtAuthentication;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class DefaultController extends Controller
{
    /**
     * @Route("/", name="home")
     */
    public function index()
    {
        return $this
            ->render('index.twig')
            ->setPublic()
            ->setMaxAge(100)
            ->setSharedMaxAge(500);
    }
    /**
     * @Route("/header", name="header")
     */
    public function header()
    {
        $response = $this
            ->render('header.twig')
            ->setPublic()
            ->setMaxAge(100)
            ->setSharedMaxAge(500);
        return $response;
    }
    /**
     * @Route("/footer", name="footer")
     */
    public function footer()
    {
        $response = $this->render('footer.twig')
            ->setMaxAge(100)
            ->setSharedMaxAge(500)
            ->setPublic();
        return $response;
    }
    /**
     * @Route("/nav", name="nav")
     */
    public function nav(Request $request)
    {
        $response =  $this->render('nav.twig')
            ->setPrivate();
        $response->headers->addCacheControlDirective('no-store');
        return $response;
    }
    /**
     * @Route("/login", name="login")
     */
    public function login(Request $request)
    {
        $response =  $this->render('login.twig',
            [
                'loginLogoutUrl' => $this->generateUrl('login'),
                'loginLogoutLabel' => 'log_in',
                'error' => $request->get('error')
            ]
        )->setPrivate();
        $response->headers->addCacheControlDirective('no-store');

        return $response;
    }
    /**
     * @Route("/logout", name="logout")
     */
    public function logout()
    {
        $response =  new RedirectResponse($this->generateUrl('login'));
        $response->headers->clearCookie('token');
        $response->setPrivate();
        $response->headers->addCacheControlDirective('no-store');
        return $response;
    }
    /**
     * @Route("/private", name="private")
     */
    public function private(Request $request)
    {
        $response =  $this->render('private.twig')
            ->setPrivate();
        $response->headers->addCacheControlDirective('no-store');
        return $response;
    }
}
