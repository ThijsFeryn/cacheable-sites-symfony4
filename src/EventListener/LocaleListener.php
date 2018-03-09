<?php
namespace App\EventListener;

use Symfony\Component\HttpKernel\Event\GetResponseEvent;

class LocaleListener
{
    public function onKernelRequest(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        $preferredLanguage = $request->getPreferredLanguage();
        if(null !== $preferredLanguage) {
            $request->setLocale($preferredLanguage);
        }
    }
}