CREATE TABLE `alert_actions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`alertId` int NOT NULL,
	`actionType` enum('acknowledged','escalated','dismissed','severity_changed','assigned') NOT NULL,
	`previousValue` varchar(64),
	`newValue` varchar(64),
	`reason` text,
	`userId` int NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `alert_actions_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `alerts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`eventId` varchar(64) NOT NULL,
	`severity` enum('critical','high','medium','low') NOT NULL DEFAULT 'medium',
	`title` varchar(255) NOT NULL,
	`description` text,
	`source` varchar(128) NOT NULL,
	`target` varchar(128),
	`eventType` varchar(64) NOT NULL,
	`rawData` json,
	`status` enum('open','acknowledged','escalated','dismissed') NOT NULL DEFAULT 'open',
	`assignedTo` int,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`incidentId` int,
	CONSTRAINT `alerts_id` PRIMARY KEY(`id`),
	CONSTRAINT `alerts_eventId_unique` UNIQUE(`eventId`)
);
--> statement-breakpoint
CREATE TABLE `incidents` (
	`id` int AUTO_INCREMENT NOT NULL,
	`incidentId` varchar(64) NOT NULL,
	`title` varchar(255) NOT NULL,
	`severity` enum('critical','high','medium','low') NOT NULL DEFAULT 'high',
	`status` enum('open','investigating','contained','resolved') NOT NULL DEFAULT 'open',
	`rootCause` text,
	`affectedAssets` json,
	`mitreAttackTactics` json,
	`killChain` json,
	`remediationSteps` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`investigationId` int,
	CONSTRAINT `incidents_id` PRIMARY KEY(`id`),
	CONSTRAINT `incidents_incidentId_unique` UNIQUE(`incidentId`)
);
--> statement-breakpoint
CREATE TABLE `investigations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`investigationId` varchar(64) NOT NULL,
	`alertIds` json,
	`status` enum('in_progress','completed','failed') NOT NULL DEFAULT 'in_progress',
	`reasoningSteps` json,
	`conclusion` text,
	`confidenceScore` decimal(3,2),
	`executedAt` timestamp,
	`completedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`userId` int NOT NULL,
	CONSTRAINT `investigations_id` PRIMARY KEY(`id`),
	CONSTRAINT `investigations_investigationId_unique` UNIQUE(`investigationId`)
);
--> statement-breakpoint
CREATE TABLE `iocs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`iocId` varchar(64) NOT NULL,
	`incidentId` int NOT NULL,
	`type` enum('ip','domain','hash','email','url','file_path') NOT NULL,
	`value` varchar(512) NOT NULL,
	`severity` enum('critical','high','medium','low') NOT NULL DEFAULT 'medium',
	`firstSeen` timestamp NOT NULL DEFAULT (now()),
	`lastSeen` timestamp NOT NULL DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `iocs_id` PRIMARY KEY(`id`),
	CONSTRAINT `iocs_iocId_unique` UNIQUE(`iocId`)
);
--> statement-breakpoint
CREATE TABLE `metrics` (
	`id` int AUTO_INCREMENT NOT NULL,
	`timestamp` timestamp NOT NULL DEFAULT (now()),
	`mttd` decimal(10,2),
	`mtta` decimal(10,2),
	`mttr` decimal(10,2),
	`openIncidentCount` int NOT NULL DEFAULT 0,
	`criticalAlertCount` int NOT NULL DEFAULT 0,
	`highAlertCount` int NOT NULL DEFAULT 0,
	`mediumAlertCount` int NOT NULL DEFAULT 0,
	`lowAlertCount` int NOT NULL DEFAULT 0,
	`acknowledgedCount` int NOT NULL DEFAULT 0,
	`dismissedCount` int NOT NULL DEFAULT 0,
	CONSTRAINT `metrics_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `action_alert_idx` ON `alert_actions` (`alertId`);--> statement-breakpoint
CREATE INDEX `action_user_idx` ON `alert_actions` (`userId`);--> statement-breakpoint
CREATE INDEX `action_createdAt_idx` ON `alert_actions` (`createdAt`);--> statement-breakpoint
CREATE INDEX `severity_idx` ON `alerts` (`severity`);--> statement-breakpoint
CREATE INDEX `status_idx` ON `alerts` (`status`);--> statement-breakpoint
CREATE INDEX `createdAt_idx` ON `alerts` (`createdAt`);--> statement-breakpoint
CREATE INDEX `incident_idx` ON `alerts` (`incidentId`);--> statement-breakpoint
CREATE INDEX `incident_severity_idx` ON `incidents` (`severity`);--> statement-breakpoint
CREATE INDEX `incident_status_idx` ON `incidents` (`status`);--> statement-breakpoint
CREATE INDEX `incident_createdAt_idx` ON `incidents` (`createdAt`);--> statement-breakpoint
CREATE INDEX `investigation_status_idx` ON `investigations` (`status`);--> statement-breakpoint
CREATE INDEX `investigation_createdAt_idx` ON `investigations` (`createdAt`);--> statement-breakpoint
CREATE INDEX `investigation_user_idx` ON `investigations` (`userId`);--> statement-breakpoint
CREATE INDEX `ioc_incident_idx` ON `iocs` (`incidentId`);--> statement-breakpoint
CREATE INDEX `ioc_type_idx` ON `iocs` (`type`);--> statement-breakpoint
CREATE INDEX `metrics_timestamp_idx` ON `metrics` (`timestamp`);