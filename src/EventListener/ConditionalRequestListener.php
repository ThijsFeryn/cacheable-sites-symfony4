<?php
namespace App\EventListener;

use Symfony\Bridge\Monolog\Logger;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use SymfonyBundles\RedisBundle\Redis\Client as RedisClient;

class ConditionalRequestListener
{
    protected $redis;
    protected $logger;
    public function __construct(RedisClient $redis)
    {
        $this->redis = $redis;
    }
    protected function isModified(Request $request, $etag)
    {
        if ($etags = $request->getETags()) {
             return in_array($etag, $etags) || in_array('*', $etags);
        }
        return true;
    }
    public function onKernelRequest(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        $etag = $this->redis->get('etag:'.md5($request->getUri()));
        if(!$this->isModified($request,$etag)) {
            $event->setResponse(Response::create('Not Modified',Response::HTTP_NOT_MODIFIED));
        }
    }
    public function onKernelResponse(FilterResponseEvent $event)
    {
        $response = $event->getResponse();
        $request = $event->getRequest();

        $etag = md5($response->getContent());
        $response->setEtag($etag);
        if($this->isModified($request,$etag)) {
            $this->redis->set('etag:'.md5($request->getUri()),$etag);
        }
    }
}