<?php

declare(strict_types=1);
// SPDX-FileCopyrightText: Tobias Knöppler <thecalcaholic@web.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\Secrets\Controller;

use OCA\Secrets\AppInfo\Application;
use OCA\Secrets\Service\SecretNotFound;
use OCA\Secrets\Service\SecretService;
use OCP\AppFramework\ApiController;
use OCP\AppFramework\Http\DataResponse;
use OCP\IURLGenerator;
use \OCP\Notification\IManager as INotificationManager;
use OCP\IRequest;
use OCP\ISession;

class SecretApiController extends ApiController {
	private INotificationManager $notificationManager;
	private SecretService $service;
	private ISession $session;
	private IURLGenerator $urlGenerator;
	private ?string $userId;

	use Errors;

	public function __construct(IRequest      $request,
								ISession $session,
                                SecretService $service,
								INotificationManager $notificationManager,
								IURLGenerator $urlGenerator) {
		parent::__construct(Application::APP_ID, $request);
		$this->notificationManager = $notificationManager;
		$this->urlGenerator = $urlGenerator;
		$this->service = $service;
		$this->session = $session;
	}

	/**
	 * @PublicPage
	 * @NoCSRFRequired
	 *
	 * @param string $uuid
	 * @return DataResponse
	 * @throws SecretNotFound
	 */
	public function getSecret(string $uuid): DataResponse {
		// TODO: Does it make sense to reenable the password parameter? Make sure to consider brute force protection
		$password = null;
		error_log($uuid);
		$secret = $this->service->findPublic($uuid);
		if ($secret->getEncrypted() === null) {
			return new DataResponse(array(), 404);
		}

		$pwHash = null;
		if ($password) {
			$pwHash = hash("sha256", $password . $secret->getUuid());
		} elseif ($this->session->get('public_link_authenticated_token') === $uuid) {
			$pwHash = $this->session->get('public_link_authenticated_password_hash');
		}
		if ($secret->getPwHash() !== null && $secret->getPwHash() !== $pwHash) {
			return new DataResponse(array(), 401);
		}

		$notificationManager = \OC::$server->get(INotificationManager::class);
		$notification = $notificationManager->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($secret->getUserId())
			->setDateTime(new DateTime())
			->setObject("secret", $secret->getUuid())
			->setSubject("Secret retrieved")
			->setIcon($this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath(Application::APP_ID, 'app.svg')))
			->setLink($this->urlGenerator->linkToRouteAbsolute('page#show', ['uuid' => $secret->getUuid()]))
			->setMessage("Secret '" . $secret->getTitle() ."' has been retrieved.");
		$notificationManager->notify($notification);

		$this->service->invalidate($secret->getUuid());

		$data = array(
			'iv' => $secret->getIv(),
			'encrypted' => $secret->getEncrypted()
		);
		return new DataResponse($data);
	}
}
