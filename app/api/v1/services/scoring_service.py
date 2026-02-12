def calculate_lead_score(lead):
    """
    Calculate lead score based on various criteria
    Score range: 0-100
    """
    score = 0
    
    # Budget scoring (0-40 points)
    budget_scores = {
        'under-100k': 10,
        '100k-250k': 20,
        '250k-500k': 30,
        '500k-1m': 35,
        'over-1m': 40
    }
    score += budget_scores.get(lead.budget, 0)
    
    # Timeline scoring (0-30 points)
    timeline_scores = {
        'immediate': 30,
        'short': 25,
        'medium': 15,
        'long': 10
    }
    score += timeline_scores.get(lead.timeline, 0)
    
    # Property type scoring (0-20 points)
    property_scores = {
        'residential': 20,
        'commercial': 18,
        'rental': 15,
        'land': 12
    }
    score += property_scores.get(lead.property_type, 0)
    
    # Message quality (0-10 points)
    if lead.message and len(lead.message.strip()) > 20:
        score += 10
    elif lead.message:
        score += 5
    
    return min(score, 100)  # Cap at 100