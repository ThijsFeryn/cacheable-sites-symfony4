<?php
namespace App\EventListener;

use Symfony\Component\HttpKernel\Event\FilterResponseEvent;

class ContentLengthListener
{
    public function onKernelResponse(FilterResponseEvent $event)
    {
        $response = $event->getResponse();
        $response->headers->set('Content-Length',strlen($response->getContent()));
    }
}