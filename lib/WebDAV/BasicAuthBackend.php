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
use Sabre\DAV\Auth\Backend\AbstractBasic;
use Sabre\DAV\Auth\Plugin;

/**
 * @template-implements IEventListener<Event>
 */
class BasicAuthBackend extends AbstractBasic implements IEventListener
{
    private string $appName;
    private IUserSession $userSession;
    private ISession $session;
    private IConfig $config;
    private LoggerInterface $logger;
    private LoginService $loginService;
    private IUserManager $userManager;
    private ISetupManager $setupManager;

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
     * @param string $username
     * @param string $password
     *
     * @return bool
     */
    #[\Override]
    public function validateUserPass($username, $password)
    {
        $this->setupFs(); // login hooks may need early access to the filesystem

        if (!$this->userSession->isLoggedIn()) {
            try {
                $this->login($username, $password);
            } catch (\Exception $e) {
                $this->logger->debug("WebDAV basic token validation failed with: {$e->getMessage()}", ['app' => $this->appName]);

                return false;
            }
        }

        if ($this->userSession->isLoggedIn()) {
            $user = $this->userSession->getUser();
            if (null !== $user) {
                $this->setupUserFs($user->getUID());

                return true;
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
            $password_auth_enabled = $this->config->getSystemValue('oidc_login_password_authentication', false);

            if ($webdav_enabled && $password_auth_enabled) {
                $authPlugin->addBackend($this);
            }
        }
    }

    private function setupUserFs(string $userId): string
    {
        $this->setupFs($userId);

        /* On the v1 route /remote.php/webdav, a default nextcloud backend
         * tries and fails to authenticate users, then close the session.
         * This is why this check is needed.
         * https://github.com/nextcloud/server/issues/31091
         */
        if (PHP_SESSION_ACTIVE === session_status()) {
            $this->session->close();
        }

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

    private function login(string $username, string $password): void
    {
        $client = $this->loginService->createOIDCClient();

        $client->addAuthParam([
            'username' => $username,
            'password' => $password,
        ]);

        $token = $client->requestResourceOwnerToken(true);

        if (null === $token) {
            throw new \Exception("Couldn't get a resource owner token");
        }

        if (isset($token->error)) {
            if (isset($token->error_description)) {
                throw new \Exception("Resource owner token error: {$token->error} {$token->error_description}");
            }

            throw new \Exception("Resource owner token error: {$token->error}");
        }

        $profile = $client->getTokenProfile($token->access_token);

        $this->loginService->login($profile);
    }
}
