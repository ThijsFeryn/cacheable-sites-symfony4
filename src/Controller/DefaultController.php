<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\RedirectResponse;
use App\Service\JwtAuthentication;

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
    public function nav(Request $request, JwtAuthentication $jwt)
    {
        if($jwt->validate($request->cookies->get('token'))) {
            $loginLogoutUrl = $loginLogoutUrl = $this->generateUrl('logout');
            $loginLogoutLabel = 'log_out';
        } else {
            $loginLogoutUrl = $this->generateUrl('login');
            $loginLogoutLabel = 'log_in';
        }
        $response =  $this->render('nav.twig', ['loginLogoutUrl'=>$loginLogoutUrl,'loginLogoutLabel'=>$loginLogoutLabel])
            ->setVary('X-Login',false)
            ->setMaxAge(100)
            ->setSharedMaxAge(500)
            ->setPublic();
        return $response;
    }
    /**
     * @Route("/login", name="login", methods="GET")
     */
    public function login(Request $request, JwtAuthentication $jwt)
    {
        if($jwt->validate($request->cookies->get('token'))) {
            return new RedirectResponse($this->generateUrl('home'));
        }
        $response =  $this->render('login.twig',['loginLogoutUrl'=>$this->generateUrl('login'),'loginLogoutLabel'=>'log_in'])
            ->setMaxAge(100)
            ->setSharedMaxAge(500)
            ->setVary('X-Login',false)
            ->setPublic();
        return $response;
    }
    /**
     * @Route("/login", name="loginpost", methods="POST")
     */
    public function loginpost(Request $request, JwtAuthentication $jwt)
    {
        $username = $request->get('username');
        $password = $request->get('password');

        if(!$username || !$password || getenv('JWT_USERNAME') != $username  || !password_verify($password,getenv('JWT_PASSWORD'))) {
            return new RedirectResponse($this->generateUrl('login'));
        }
        $response = new RedirectResponse($this->generateUrl('home'));
        $response->headers->setCookie($jwt->createCookie($username));
        return $response;
    }
    /**
     * @Route("/logout", name="logout")
     */
    public function logout()
    {
        $response = new RedirectResponse($this->generateUrl('login'));
        $response->headers->clearCookie('token');
        return $response;
    }
    /**
     * @Route("/private", name="private")
     */
    public function private(Request $request, JwtAuthentication $jwt)
    {
        if(!$jwt->validate($request->cookies->get('token'))) {
            return new RedirectResponse($this->generateUrl('login'));
        }
        $response =  $this->render('private.twig')
            ->setMaxAge(100)
            ->setSharedMaxAge(500)
            ->setPublic();
        return $response;
    }
}
