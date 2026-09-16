<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\WebDAV;

use OCA\DAV\Events\SabrePluginAuthInitEvent;
use OCA\OIDCLogin\Service\LoginService;
use OCP\Defaults;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Files\ISetupManager;
use OCP\IConfig;
use OCP\ISession;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\SabrePluginEvent;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Auth\Backend\AbstractBearer;
use Sabre\DAV\Auth\Plugin;

/**
 * @template-implements IEventListener<Event>
 */
class BearerAuthBackend extends AbstractBearer implements IEventListener
{
    private string $appName;
    private IUserSession $userSession;
    private ISession $session;
    private IConfig $config;
    private LoggerInterface $logger;
    private LoginService $loginService;
    private IUserManager $userManager;
    private ISetupManager $setupManager;
    private string $principalPrefix;

    public function __construct(
        string $appName,
        IUserSession $userSession,
        ISession $session,
        IConfig $config,
        LoggerInterface $logger,
        LoginService $loginService,
        IUserManager $userManager,
        ISetupManager $setupManager,
        string $principalPrefix = 'principals/users/'
    ) {
        $this->appName = $appName;
        $this->userSession = $userSession;
        $this->session = $session;
        $this->config = $config;
        $this->logger = $logger;
        $this->loginService = $loginService;
        $this->userManager = $userManager;
        $this->setupManager = $setupManager;
        $this->principalPrefix = $principalPrefix;

        // setup realm
        $defaults = new Defaults();
        $this->realm = $defaults->getName();
    }

    /**
     * @param string $bearerToken
     *
     * @return false|string
     */
    #[\Override]
    public function validateBearerToken($bearerToken)
    {
        $this->setupFs(); // login hooks may need early access to the filesystem

        if (!$this->userSession->isLoggedIn()) {
            try {
                $this->login($bearerToken);
            } catch (\Exception $e) {
                $this->logger->debug("WebDAV bearer token validation failed with: {$e->getMessage()}", ['app' => $this->appName]);

                return false;
            }
        }

        if ($this->userSession->isLoggedIn()) {
            $user = $this->userSession->getUser();
            if (null !== $user) {
                return $this->setupUserFs($user->getUID());
            }
        }

        return false;
    }

    /**
     * Implements IEventListener::handle.
     * Registers this class as an authentication backend with Sabre WebDav.
     */
    #[\Override]
    public function handle(Event $event): void
    {
        if (!$event instanceof SabrePluginAuthInitEvent
            && !$event instanceof SabrePluginEvent) {
            return;
        }

        $server = $event->getServer();
        if (null === $server) {
            return;
        }
        $authPlugin = $server->getPlugin('auth');
        if ($authPlugin instanceof Plugin) {
            $webdav_enabled = $this->config->getSystemValue('oidc_login_webdav_enabled', false);

            if ($webdav_enabled) {
                $authPlugin->addBackend($this);
            }
        }
    }

    private function setupUserFs(string $userId): string
    {
        $this->setupFs($userId);
        $this->session->close();

        return $this->principalPrefix.$userId;
    }

    /** Set up the user filesystem, or root if no user is available. */
    private function setupFs(?string $userId = null): void
    {
        if (null === $userId) {
            $user = $this->userSession->getUser();
        } else {
            $user = $this->userManager->get($userId);
        }

        if (null !== $user) {
            $this->setupManager->setupForUser($user);
        } else {
            // A path without a user falls back to root setup internally
            $this->setupManager->setupForPath('/');
        }
    }

    /**
     * Tries to log in a user based on the given $bearerToken.
     *
     * @param string $bearerToken an OIDC JWT bearer token
     */
    private function login(string $bearerToken): void
    {
        $client = $this->loginService->createOIDCClient();

        $client->validateBearerToken($bearerToken);

        $profile = $client->getTokenProfile($bearerToken);

        $this->loginService->login($profile);
    }
}
