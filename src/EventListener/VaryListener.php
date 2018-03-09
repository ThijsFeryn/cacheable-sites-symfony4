<?php
namespace App\EventListener;

use Symfony\Component\HttpKernel\Event\FilterResponseEvent;

class VaryListener
{
    public function onKernelResponse(FilterResponseEvent $event)
    {
        $response = $event->getResponse();
        $response->setVary('Accept-Language',false);
    }
}