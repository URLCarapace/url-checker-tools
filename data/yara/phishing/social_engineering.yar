/*
 * Social Engineering Detection Rules
 * Author: URL Checker Security Team
 * Updated: 2025-09-01
 *
 * Focus: Prize scams, urgent actions, and emotional manipulation
 */

rule Prize_And_Reward_Scams
{
    meta:
        description = "Detects prize and reward scam tactics"
        author = "Security Team"
        severity = "medium"
        category = "social_engineering"

    strings:
        // Prize language with action requirements
        $prize_action1 = /(congratulations|winner|selected|chosen).*(?:claim|collect|receive).*(?:prize|reward|money|gift)/i
        $prize_action2 = /(you.*(?:won|earned|qualified)).*(?:claim|verify|confirm|update).*(?:account|details|information)/i
        $prize_action3 = /(exclusive|limited|special).*(?:offer|deal|promotion).*(?:expires|limited|act|claim)/i

        // Fake lottery/sweepstakes
        $lottery_scam = /(lottery|sweepstakes|raffle).*(?:winner|selected|notification).*(?:claim|verify|confirm)/i

        // Investment/crypto scams
        $investment_scam = /(guaranteed.*(?:profit|return|income)|crypto.*(?:opportunity|investment|mining)).*(?:register|deposit|invest|join)/i

        // Romance/advance fee fraud indicators
        $romance_scam = /(lonely|widow|inheritance|beneficiary).*(?:trust|money|transfer|help).*(?:urgent|confidential|secret)/i

    condition:
        any of them
}

rule Emotional_Manipulation_Tactics
{
    meta:
        description = "Detects emotional manipulation in phishing attempts"
        author = "Security Team"
        severity = "medium"
        category = "social_engineering"

    strings:
        // Fear-based urgency
        $fear_urgency1 = /(account.*(?:suspended|locked|compromised|closed)).*(?:restore|reactivate|verify|secure)/i
        $fear_urgency2 = /(security.*(?:breach|alert|warning)).*(?:immediate|urgent|within.*hours)/i
        $fear_urgency3 = /(unauthorized.*(?:access|login|transaction)).*(?:verify|secure|protect|confirm)/i

        // FOMO (Fear of Missing Out)
        $fomo1 = /(limited.*time|expires.*(?:today|soon|hours)|act.*(?:now|quickly|immediately))/i
        $fomo2 = /(miss.*(?:chance|opportunity)|last.*(?:chance|warning|notice))/i

        // Authority pressure
        $authority_pressure = /(must.*(?:verify|update|confirm)|required.*(?:action|verification|update)).*(?:immediately|urgent|within)/i

        // Legitimacy mimicry
        $fake_security = /(secure.*(?:connection|login|verification)|encrypted.*(?:form|transaction|communication))/i

    condition:
        // Require multiple emotional manipulation tactics
        (any of ($fear_urgency*) and any of ($fomo*)) or
        ($authority_pressure and $fake_security) or
        (2 of ($fear_urgency*))
}
