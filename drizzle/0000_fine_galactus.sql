CREATE TABLE `scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`sessionId` varchar(64) NOT NULL,
	`inputMode` enum('message','link','screenshot') NOT NULL,
	`contentHash` varchar(64) NOT NULL,
	`riskScore` int NOT NULL,
	`verdict` varchar(32) NOT NULL,
	`source` varchar(32) NOT NULL,
	`signals` text NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scans_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` int AUTO_INCREMENT NOT NULL,
	`openId` varchar(64) NOT NULL,
	`name` text,
	`email` varchar(320),
	`loginMethod` varchar(64),
	`role` enum('user','admin') NOT NULL DEFAULT 'user',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`lastSignedIn` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `users_id` PRIMARY KEY(`id`),
	CONSTRAINT `users_openId_unique` UNIQUE(`openId`)
);
--> statement-breakpoint
CREATE INDEX `scans_session_created_idx` ON `scans` (`sessionId`,`createdAt`);--> statement-breakpoint
CREATE INDEX `scans_created_idx` ON `scans` (`createdAt`);