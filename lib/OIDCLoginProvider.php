<?php

declare(strict_types=1);

namespace OCA\OIDCLogin;

use OCP\Authentication\IAlternativeLoginProvider;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IURLGenerator;

class OIDCLoginProvider implements IAlternativeLoginProvider
{
    public function __construct(
        private IURLGenerator $url,
        private IL10N $l,
        private IConfig $config,
        private IRequest $request,
    ) {}

    #[\Override]
    public function getAlternativeLogins(): array
    {
        return [new OIDCLoginOption($this->url, $this->l, $this->config, $this->request)];
    }
}
